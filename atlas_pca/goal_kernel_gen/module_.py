import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import atlas_pca.goal_kernel_gen.module_ as module_
import atlas_pca.goal_kernel_gen._dafny as _dafny
import atlas_pca.goal_kernel_gen.System_ as System_
import atlas_pca.goal_kernel_gen.GoalIr as GoalIr
import atlas_pca.goal_kernel_gen.GoalCompile as GoalCompile
import atlas_pca.goal_kernel_gen.GoalWitness as GoalWitness
import atlas_pca.goal_kernel_gen.GoalRender as GoalRender
import atlas_pca.goal_kernel_gen.GoalApi as GoalApi

# Module: module_

