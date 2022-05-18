Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB56MSSKAMGQEE5U5JWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 747B252BFD9
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:01:44 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-eda835f171sf1412381fac.6
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:01:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893303; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZOw6vlij/neVJT02qrLzEBwBtl8I2u+4Y73OmSL8Z9u81R8i0XZGU7ovxB7c8ORFS
         yDGtQBmU48lUc1gGnd+Ky0XiJgen4TZ0LgtgLayblXGogJkGMInbLrO74dFCoE0aOfPH
         lXWmKYnLyCtSjLs2/yhtg5gWEiLWV3ZCrSbqH1IZJBetBFLcH6mgCbPtX8jesjGVQeO9
         7l4ufWl9x07D4fxgUL7WCG7eFvopTX0rNTHfpiH2xWLVAlh58UHL4ti5C8F11Z1+8LSf
         NpwM4HglDF1vBepASvWiLln+kqY73shQBIlu7U++Lzlpm5/KbgIlBXVCURbF59XdHJv7
         70Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bo/x5Rqx6IHrPI86QKTCxP5oqZEiZgFzy3sSeGmtGHo=;
        b=tYBC21WN4i6uvsQkjeBZG8y08IyJqgSiLSQemUSRRBqkvhLPJButUVE8CW9QoyvyK7
         aUKNAEux4zbx5UOUNBkv+dGdQnwajgQ33NKels0LTLrpJBZeOnY4lDCzgy5Y6WuK0Zg1
         r5fzd2T4PN5wb6b1UIxRobDWSXeFe2vhE930NgKWdlcainge3nXPI8+tS8+82QcTxXYX
         rvG7+MjkdDxk+3h6JEhmf+qv7Kbd9cWJ0VdfKqCzEbYwbkW6vES0R9+aQ41xnkPtfP9B
         X/lSsUP2CpxTIK4CakvFZ2tzOwaJ5f4KP8MB69SEgXT4x2DiT8YdOfSxlOSrjHnjorJL
         18NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=koWCgoV1;
       spf=pass (google.com: domain of 3diafyggkcfewetmrihozhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3diaFYggKCfEWeTmrihoZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bo/x5Rqx6IHrPI86QKTCxP5oqZEiZgFzy3sSeGmtGHo=;
        b=rcObqucMvfC6LmAKPjZ7XA++Rc7jjCfc0rHg122p1+jLTMcAFmCd4w1a2Kkw+2tGQ+
         Tlki0odxuKx8P/Nriw+F8ysv0bpx84zzqcuLoZEfsBXRp2DDYwpMonOYPBjhILU6o+Br
         wmEJLV0bqUhxx60b79VZoxzU2cPm3CG/lWa1GVQeFaaqnAWqMm9TlNrySCujCxs5G/Is
         hSWYI5p9hGI8jfiluKSEvhANHZbmiqU6vytuf6y1WYconONzRwn6hLeFw/l4XN90axhr
         69UZcUpugJrlMdqiEU+R0zeCQRAttDDwdbA3bcBio4LZpJqOOQyhmTZ3gBbej89isT3H
         lTZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bo/x5Rqx6IHrPI86QKTCxP5oqZEiZgFzy3sSeGmtGHo=;
        b=Fk7qZn24xSm/5Me0yGsA46d7fWsXRG4s+C2nPsCX0FjE4CwL473BwI6aSL736e+8dd
         4MV6hogZhvJm7JkY4p6/htY79B0HFswY5skIpJ2ELGcsmepYokpC5M0bDvrvs2uRR5Bm
         0nVSfmeJUHapxsY8zh1UBnbNta8AVtpOxecGPD3y2AkMmsvN/tYCHlAfjf56LmnZSWni
         wXkSU9AfMzxJHwBFqCtS3kP31w+saQgDGma4CridnilNuxlvem8k2cyfWtQTRwxgB+cp
         e5XZzFgam0lXmOHmOT8TypPrdFJr5ywUse36vlrsm9fYtIeYEgn3A+zfYqH2lVlmqYGQ
         hlLg==
X-Gm-Message-State: AOAM533VEb4vO4ybi8w5Rkzb4iRmCCXRnCSsqkB/W09GlMRr/nTvGO2V
	r1kVupapkYZE+Yf05XxW6XI=
X-Google-Smtp-Source: ABdhPJzn0wD04MKrlZ6JXmFZs+mtzyCWMmqNkPdXRxwfWuZs/O3dXH0FIthDL507vB4T/29g/YuDQA==
X-Received: by 2002:a4a:91d7:0:b0:35f:25e9:8f8c with SMTP id e23-20020a4a91d7000000b0035f25e98f8cmr264522ooh.21.1652893303102;
        Wed, 18 May 2022 10:01:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4e1b:0:b0:5c9:3fe6:39de with SMTP id p27-20020a9d4e1b000000b005c93fe639dels94478otf.4.gmail;
 Wed, 18 May 2022 10:01:42 -0700 (PDT)
X-Received: by 2002:a05:6830:2693:b0:60a:c590:8382 with SMTP id l19-20020a056830269300b0060ac5908382mr259990otu.344.1652893302643;
        Wed, 18 May 2022 10:01:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893302; cv=none;
        d=google.com; s=arc-20160816;
        b=GWrIx6g2KaVKkWFVysl1i1aFieEvQVWj73fobXRPO5s1Fzl6Tn7/zy7F54ki9TV0Sa
         xjzk8PPL2N1ccKS5FXzD8+ya6clUtpHR7yAK2zj/QbfCSwU+g988oWh1yqd3ALfC8IdV
         GDLtAEJxnvIXbCwoh3zUrnbMlAo42U5yJ2MNZhzAVljkEaWeeuEvbIGPD64B61GuxKxd
         lmlIMJGU7l9j2R0VkehIwtio+nUpysfCuBqKnfwnLFyZXXQU1EBEVRZO9PFYtrb/0Fgd
         8bK0WT/3MZoZCvFM4yYHDayUNAY5YS5KlD9up6v46inQugMMr8HUBKwVjRf1LlDq7MK7
         G5UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=pKq+ukUxGkB6N6xyDoqejZhxcnXMWWmls9VVeK1R/Co=;
        b=y3gAcC9ZQ6lCYWLsEzjxplfWJGWreoFYE3kkA4NpQjz5U/pGQ/PKoaWk6/uKK4qsYL
         k+ZhekoDUgsp1k0puS8m6Z+6iTSoVaia5Aq2zSMFa1O6WxLA9oF2dgRgQJ+gdwAVEBWL
         645mwTen89gPJlc2wKQl8gTWUwgFS1+VG+CmjYmMKqKMtgZ8vPAy0p2xZCUzdXzd7DI8
         nN+yQbAsgfkPfsiM70k/jIek2qvyFX3xu31feDdECr9rks5P3Jg9cKWXTvCcd6TzJImq
         A+51HOOyPRbsBsQ7YqDSKBKl8nk8LcKAGNHwWK8+UP7NHXIg2gXScF4uHQCMcbgI+XBl
         Akpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=koWCgoV1;
       spf=pass (google.com: domain of 3diafyggkcfewetmrihozhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3diaFYggKCfEWeTmrihoZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id u39-20020a056870d5a700b000f1e0ccdd86si71079oao.3.2022.05.18.10.01.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:01:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3diafyggkcfewetmrihozhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-2ff40ee8109so22083627b3.14
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:01:42 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:a94f:2cb3:f298:ec1b])
 (user=dlatypov job=sendgmr) by 2002:a25:186:0:b0:64d:7067:226 with SMTP id
 128-20020a250186000000b0064d70670226mr560357ybb.446.1652893302212; Wed, 18
 May 2022 10:01:42 -0700 (PDT)
Date: Wed, 18 May 2022 10:01:24 -0700
In-Reply-To: <20220518170124.2849497-1-dlatypov@google.com>
Message-Id: <20220518170124.2849497-4-dlatypov@google.com>
Mime-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com>
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH 3/3] kunit: tool: introduce --qemu_args
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: elver@google.com, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	skhan@linuxfoundation.org, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=koWCgoV1;       spf=pass
 (google.com: domain of 3diafyggkcfewetmrihozhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3diaFYggKCfEWeTmrihoZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Example usage:
$ ./tools/testing/kunit/kunit.py run --arch=x86_64 \
  --kconfig_add=CONFIG_SMP=y --qemu_args='-smp 8'

Looking in the test.log, one can see
> smp: Bringing up secondary CPUs ...
> .... node  #0, CPUs:      #1 #2 #3 #4 #5 #6 #7
> smp: Brought up 1 node, 8 CPUs

This flag would allow people to make tweaks like this without having to
create custom qemu_config files.

For consistency with --kernel_args, we allow users to repeat this
argument, e.g. you can tack on a --qemu_args='-m 2048', or you could
just append it to the first string ('-smp 8 -m 2048').

Signed-off-by: Daniel Latypov <dlatypov@google.com>
---
 tools/testing/kunit/kunit.py           | 14 +++++++++++++-
 tools/testing/kunit/kunit_kernel.py    | 10 +++++++---
 tools/testing/kunit/kunit_tool_test.py | 20 +++++++++++++++++---
 3 files changed, 37 insertions(+), 7 deletions(-)

diff --git a/tools/testing/kunit/kunit.py b/tools/testing/kunit/kunit.py
index 8a90d80ee66e..e01c7964f744 100755
--- a/tools/testing/kunit/kunit.py
+++ b/tools/testing/kunit/kunit.py
@@ -10,6 +10,7 @@
 import argparse
 import os
 import re
+import shlex
 import sys
 import time
 
@@ -323,6 +324,10 @@ def add_common_opts(parser) -> None:
 				  'a QemuArchParams object.'),
 			    type=str, metavar='FILE')
 
+	parser.add_argument('--qemu_args',
+			    help='Additional QEMU arguments, e.g. "-smp 8"',
+			    action='append', metavar='')
+
 def add_build_opts(parser) -> None:
 	parser.add_argument('--jobs',
 			    help='As in the make command, "Specifies  the number of '
@@ -368,12 +373,19 @@ def add_parse_opts(parser) -> None:
 
 def tree_from_args(cli_args: argparse.Namespace) -> kunit_kernel.LinuxSourceTree:
 	"""Returns a LinuxSourceTree based on the user's arguments."""
+	# Allow users to specify multiple arguments in one string, e.g. '-smp 8'
+	qemu_args: List[str] = []
+	if cli_args.qemu_args:
+		for arg in cli_args.qemu_args:
+			qemu_args.extend(shlex.split(arg))
+
 	return kunit_kernel.LinuxSourceTree(cli_args.build_dir,
 			kunitconfig_path=cli_args.kunitconfig,
 			kconfig_add=cli_args.kconfig_add,
 			arch=cli_args.arch,
 			cross_compile=cli_args.cross_compile,
-			qemu_config_path=cli_args.qemu_config)
+			qemu_config_path=cli_args.qemu_config,
+			extra_qemu_args=qemu_args)
 
 
 def main(argv):
diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
index e93f07ac0af1..a791073d25f9 100644
--- a/tools/testing/kunit/kunit_kernel.py
+++ b/tools/testing/kunit/kunit_kernel.py
@@ -187,6 +187,7 @@ def _default_qemu_config_path(arch: str) -> str:
 	raise ConfigError(arch + ' is not a valid arch, options are ' + str(sorted(options)))
 
 def _get_qemu_ops(config_path: str,
+		  extra_qemu_args: Optional[List[str]],
 		  cross_compile: Optional[str]) -> Tuple[str, LinuxSourceTreeOperations]:
 	# The module name/path has very little to do with where the actual file
 	# exists (I learned this through experimentation and could not find it
@@ -207,6 +208,8 @@ def _get_qemu_ops(config_path: str,
 	if not hasattr(config, 'QEMU_ARCH'):
 		raise ValueError('qemu_config module missing "QEMU_ARCH": ' + config_path)
 	params: qemu_config.QemuArchParams = config.QEMU_ARCH  # type: ignore
+	if extra_qemu_args:
+		params.extra_qemu_params.extend(extra_qemu_args)
 	return params.linux_arch, LinuxSourceTreeOperationsQemu(
 			params, cross_compile=cross_compile)
 
@@ -220,17 +223,18 @@ class LinuxSourceTree:
 	      kconfig_add: Optional[List[str]]=None,
 	      arch=None,
 	      cross_compile=None,
-	      qemu_config_path=None) -> None:
+	      qemu_config_path=None,
+	      extra_qemu_args=None) -> None:
 		signal.signal(signal.SIGINT, self.signal_handler)
 		if qemu_config_path:
-			self._arch, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
+			self._arch, self._ops = _get_qemu_ops(qemu_config_path, extra_qemu_args, cross_compile)
 		else:
 			self._arch = 'um' if arch is None else arch
 			if self._arch == 'um':
 				self._ops = LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
 			else:
 				qemu_config_path = _default_qemu_config_path(self._arch)
-				_, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
+				_, self._ops = _get_qemu_ops(qemu_config_path, extra_qemu_args, cross_compile)
 
 		if kunitconfig_path:
 			if os.path.isdir(kunitconfig_path):
diff --git a/tools/testing/kunit/kunit_tool_test.py b/tools/testing/kunit/kunit_tool_test.py
index baee11d96474..7fe5c8b0fb57 100755
--- a/tools/testing/kunit/kunit_tool_test.py
+++ b/tools/testing/kunit/kunit_tool_test.py
@@ -649,7 +649,8 @@ class KUnitMainTest(unittest.TestCase):
 						kconfig_add=None,
 						arch='um',
 						cross_compile=None,
-						qemu_config_path=None)
+						qemu_config_path=None,
+						extra_qemu_args=[])
 
 	def test_config_kunitconfig(self):
 		kunit.main(['config', '--kunitconfig=mykunitconfig'])
@@ -659,7 +660,8 @@ class KUnitMainTest(unittest.TestCase):
 						kconfig_add=None,
 						arch='um',
 						cross_compile=None,
-						qemu_config_path=None)
+						qemu_config_path=None,
+						extra_qemu_args=[])
 
 	def test_run_kconfig_add(self):
 		kunit.main(['run', '--kconfig_add=CONFIG_KASAN=y', '--kconfig_add=CONFIG_KCSAN=y'])
@@ -669,7 +671,19 @@ class KUnitMainTest(unittest.TestCase):
 						kconfig_add=['CONFIG_KASAN=y', 'CONFIG_KCSAN=y'],
 						arch='um',
 						cross_compile=None,
-						qemu_config_path=None)
+						qemu_config_path=None,
+						extra_qemu_args=[])
+
+	def test_run_qemu_args(self):
+		kunit.main(['run', '--arch=x86_64', '--qemu_args', '-m 2048'])
+		# Just verify that we parsed and initialized it correctly here.
+		self.mock_linux_init.assert_called_once_with('.kunit',
+						kunitconfig_path=None,
+						kconfig_add=None,
+						arch='x86_64',
+						cross_compile=None,
+						qemu_config_path=None,
+						extra_qemu_args=['-m', '2048'])
 
 	def test_run_kernel_args(self):
 		kunit.main(['run', '--kernel_args=a=1', '--kernel_args=b=2'])
-- 
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518170124.2849497-4-dlatypov%40google.com.
