// SPDX-License-Identifier: MIT
export const url = import.meta.url;
export function run() {
  rpc.exports = {add(a, b) { return a + b; }};
}
