// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use crate::core::link::{self, LinkedList, Node};
use crate::core::nodes::NodeRef;
use std::collections::HashMap;
use std::ptr::NonNull;

struct MapNode<T> {
    ptr: NonNull<Node<u64>>,
    node: NodeRef<T>,
}

pub struct Iter<'a, T: 'a> {
    iter: link::Iter<'a, u64>,
    map: &'a HashMap<u64, MapNode<T>>,
}

pub struct IterMut<'a, T: 'a> {
    iter: link::Iter<'a, u64>,
    map: &'a HashMap<u64, MapNode<T>>,
}

pub struct LruCache<T> {
    list: LinkedList<u64>,
    map: HashMap<u64, MapNode<T>>,
}

impl<T> Default for LruCache<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LruCache<T> {
    #[inline]
    pub fn new() -> LruCache<T> {
        LruCache {
            list: LinkedList::new(),
            map: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> LruCache<T> {
        LruCache {
            list: LinkedList::new(),
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn add(&mut self, key: u64, data: NodeRef<T>) -> bool {
        if self.map.get(&key).is_some() {
            false
        } else {
            self.list.push_front(key);
            let node = unsafe { self.list.head_node().unwrap() };
            self.map.insert(
                key,
                MapNode {
                    ptr: node,
                    node: data,
                },
            );
            true
        }
    }

    // bump it to the head
    pub fn bump(&mut self, key: u64) {
        let map_node = match self.map.get_mut(&key) {
            Some(node) => node,
            None => return,
        };
        unsafe {
            self.list.move_to_head(map_node.ptr);
        }
    }

    pub fn find(&self, key: u64) -> Option<NodeRef<T>> {
        self.map.get(&key).map(|map_node| map_node.node.clone())
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn pop_front(&mut self) -> Option<NodeRef<T>> {
        let key = self.list.pop_front()?;
        self.map.remove(&key).map(|map_node| map_node.node)
    }

    pub fn pop_back(&mut self) -> Option<NodeRef<T>> {
        let key = self.list.pop_back()?;
        self.map.remove(&key).map(|map_node| map_node.node)
    }

    pub fn front(&self) -> Option<&NodeRef<T>> {
        let key = self.list.front()?;
        self.map.get(key).map(|map_node| &map_node.node)
    }

    pub fn front_mut(&mut self) -> Option<&mut NodeRef<T>> {
        let key = self.list.front()?;
        self.map.get_mut(key).map(|map_node| &mut map_node.node)
    }

    pub fn back(&self) -> Option<&NodeRef<T>> {
        let key = self.list.back()?;
        self.map.get(key).map(|map_node| &map_node.node)
    }

    pub fn back_mut(&mut self) -> Option<&mut NodeRef<T>> {
        let key = self.list.back()?;
        self.map.get_mut(key).map(|map_node| &mut map_node.node)
    }

    pub fn clear(&mut self) {
        self.list.clear();
        self.map.clear();
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            iter: self.list.iter(),
            map: &self.map,
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut {
            iter: self.list.iter(),
            map: &mut self.map,
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a NodeRef<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.iter.next()?;
        self.map.get(key).map(|map_node| &map_node.node)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut NodeRef<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.iter.next()?;
        self.map.get(key).map(|map_node| unsafe {
            let node = &map_node.node as *const _ as *mut _;
            &mut *node
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        let (len, _) = self.iter.size_hint();
        if len == 0 {
            None
        } else {
            let key = self.iter.next_back()?;
            self.map.get(key).map(|map_node| &map_node.node)
        }
    }
}

impl<T> DoubleEndedIterator for IterMut<'_, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        let (len, _) = self.iter.size_hint();
        if len == 0 {
            None
        } else {
            let key = self.iter.next_back()?;
            self.map.get(key).map(|map_node| unsafe {
                let node = &map_node.node as *const _ as *mut _;
                &mut *node
            })
        }
    }
}

pub struct IntoIter<T> {
    cache: LruCache<T>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = NodeRef<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.cache.pop_front()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.cache.len(), Some(self.cache.len()))
    }
}

impl<T> DoubleEndedIterator for IntoIter<T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.cache.pop_back()
    }
}

impl<T> IntoIterator for LruCache<T> {
    type Item = NodeRef<T>;
    type IntoIter = IntoIter<T>;

    /// Consumes the list into an iterator yielding elements by value.
    #[inline]
    fn into_iter(self) -> IntoIter<T> {
        IntoIter { cache: self }
    }
}

impl<'a, T> IntoIterator for &'a LruCache<T> {
    type Item = &'a NodeRef<T>;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut LruCache<T> {
    type Item = &'a mut NodeRef<T>;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}
