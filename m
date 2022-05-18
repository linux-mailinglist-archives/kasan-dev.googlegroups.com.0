Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB5OMSSKAMGQESZFWLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 234D152BFD7
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:01:43 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id f9-20020a636a09000000b003c61848e622sf1473377pgc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893301; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZTc6rL3GLB0qsh2Y09mjXn2XCPIsi/kEhy6uEktg5HVnpVf5++5MJTiEO8mR3MajB
         8lQwLogU6OBCKP1TCFNixMz24AdmvaE8dI4mdXxEcjw8rRZMasRqfSFso+FTvrdpDFNc
         oOggsD6LXV3buZ2+bUE9cqS0Jy8oixetgBpzlVB4Cpkwhh50scf5n2xIzU7i7gPoYsyt
         KqpjK4G/OXzRVInJzzmdudmLOMvfoWSvl4GAxGSxQidXbMJnYqr42uXZ+Fccd0b+7g84
         KnLry4Plww1DQSZVWmZ/UmdojBcei5U11U6B/gJI8VcKCdN6LU//nwmvafSFRnzUVhln
         OXtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CLayB8Ci0ypgaKkKaxsyyTiJSVm4F6v2e792pSVL+fg=;
        b=D+5FLMMlgg9FiKP4gIda3hgOSWo/OhlMeid2GjpLAMHWV+7SIEQ34syw4aS2rz5sQY
         x8/YBKhf9NrP2kZNj104ocL58UAgrGN3dYQoquEKnUSKIHimhLShzGw1u7454fzWFjl8
         2i5I+RdBlPzXyNHrlpjnWHcAMv3Ic/i+SYrMA04LGq+NPdfe8LR6i6Jeu9NKPEqgQVA6
         qyg260olho9UoEPkmcLI2iE1EeIA8E8gYySU7g33WJgxmReWy3VXnq1RpOzy5vfUe2Vx
         7lKqUqdym5A4ShAAbBlEDqrjrKH9/nNNRxJ4Pc8UebVWiC+SNiHS7ouWmzorFlhLQ/b1
         eBuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o5OhYnQd;
       spf=pass (google.com: domain of 3dcafyggkce8ucrkpgfmxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dCaFYggKCe8UcRkpgfmXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CLayB8Ci0ypgaKkKaxsyyTiJSVm4F6v2e792pSVL+fg=;
        b=qeu9PeiZ88715lTjcbgnCJWo1YSTTUJqYI1+6U9ifD2G3/Qr3oJaXd2k+zfuvOLEkP
         xQOdH9aDUa09W/qXdDEESz7MTZoR4N9GWeanq34zqNBMb2Yy7sPBKQFRrWwgblLnwYsB
         MOCt0gLksIpwc99iSsG0JuHGaqqGQmL7isywe/PnBjzBjzaPYKaSdZ0WpqNiIxbvXStZ
         JITc9aLKRxwQEVHS6EUnGXlMrHlqjcIavKlR+aj4SOVpEFfPVgVFEH9/E/nrOCHj1ELz
         +q9TJ0xANJ5tNVNTuIHf7MLJX/vjChIF20pJ4+UUekpPgOekMb1Xmro0UU67sKGkOiwA
         EiDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CLayB8Ci0ypgaKkKaxsyyTiJSVm4F6v2e792pSVL+fg=;
        b=BDuGxvsvlfMwZCwZoAyFeocWkJ09fzK2Ikq7g+kNHuATWHZMi2QC89qDUdsjBUK/Or
         UXw9ShcbLZ6I0uXv4AF7l0cyFXTiWeur05RtSFMG7lOoxvNRWlXVBhOJhXlLp/YezW3G
         7yj/IHNSOc9i+PJIrv89R7hztVqa1EeZsQLwoahzGW29aMMXDdk8gA92CasYRb6yDqbm
         7T0lNnyCb9iaZ5GiHxltApH7nDsJI9QhLlzgDY0jUw77eii1G2vsBcWuyKDHN2ShjquQ
         Y1vVDObAEWyuZhRYa/+3X1EMFJ/dLS+Qi6OCJrdO4E9+dOgjjfoG7KG5utVSOhJ+jfqC
         sIcA==
X-Gm-Message-State: AOAM531h2UzOMXo+2vDobMODGsstrBh3iuDzrdcVBqIxYRJ+HTZm8vky
	TRWZVUpjvzFuJdjrGgQK76c=
X-Google-Smtp-Source: ABdhPJxoobHSqTQzXA/yLe/JUwcfB08pzz8Ic/NzKChPmObpwkgloXzSTOoCKK2olndwSEGkFL6n3A==
X-Received: by 2002:a63:cc53:0:b0:372:7d69:49fb with SMTP id q19-20020a63cc53000000b003727d6949fbmr348934pgi.21.1652893301473;
        Wed, 18 May 2022 10:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4f58:0:b0:3c1:5bb1:608 with SMTP id p24-20020a634f58000000b003c15bb10608ls110748pgl.6.gmail;
 Wed, 18 May 2022 10:01:40 -0700 (PDT)
X-Received: by 2002:a05:6a00:1908:b0:4f7:8813:b2cb with SMTP id y8-20020a056a00190800b004f78813b2cbmr320386pfi.54.1652893300788;
        Wed, 18 May 2022 10:01:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893300; cv=none;
        d=google.com; s=arc-20160816;
        b=sZoS7ZmQuw/6D0YpA9VAP2zBVqcrPcBgxg9wg3ZsTEei80+UCgLrdY8fPAaLlMS58n
         DoY2UZ1mY0oizsV/k0JAJtauF1UNtimZ1SsLcUZOokq604v5sEHJLWh5/dW0lHzvuuu2
         uFFM+6AMGm4GzNepTMKl63+0s6m8YR4IH3hytnpGhUeyCHcRM/T1h1Kwz7Z8slxb17qt
         yXZr/qVaU64i7lo9E899nTtUz2xdMQkJw5UX97lD63myhgqNnUY3n03d0rBNyzduAByX
         +xeDHq9C9u5/1K6DqG1GbbvpxFZvI8G9IGhDFBcFe3vKSs5GWOPCHVBUHCyk4Aih12Mo
         UB6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=4p2OIzyLZf5DSGNOpJEFrH/AUMGocyU2gKg4RrUCI6s=;
        b=mKJebp/sF3hHbbgWH9d7SCD6WmMCz1G1uQPnJMPt7JElHVCXBbFyHSyPDNwMMr3bdL
         IQ+OW/ZYeuInSmxLbuXPLilU+q0wyOpYZiMyi0gn5kALSeqoAb0koODO2yDH6YCWlp2D
         LEQef39YsTj0GxNY9ZSI53NGjsxfg//kVnyeTi9EN9WAy06ac8+AU2Hyw3GwnTLcchd9
         UWe8+MQl4TpKjvBkV1BH540Vs6kDuSqUGMqz9cNH5YKnTfcrTD4LtOTHlBsi2tdzuvTt
         hP8MHJvDcjKmlrPLKgG0go1P6gtVxY2/Qmt/qvl7mg5Np6NwKx58LkRoSYzvWdKdkWGm
         N/IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o5OhYnQd;
       spf=pass (google.com: domain of 3dcafyggkce8ucrkpgfmxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dCaFYggKCe8UcRkpgfmXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d2-20020a170902728200b00156542d2ad8si115925pll.10.2022.05.18.10.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:01:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dcafyggkce8ucrkpgfmxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2fefb9975c5so23705927b3.21
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:01:40 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:a94f:2cb3:f298:ec1b])
 (user=dlatypov job=sendgmr) by 2002:a81:bb49:0:b0:2fe:e07b:9a6c with SMTP id
 a9-20020a81bb49000000b002fee07b9a6cmr415296ywl.136.1652893300072; Wed, 18 May
 2022 10:01:40 -0700 (PDT)
Date: Wed, 18 May 2022 10:01:23 -0700
In-Reply-To: <20220518170124.2849497-1-dlatypov@google.com>
Message-Id: <20220518170124.2849497-3-dlatypov@google.com>
Mime-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com>
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH 2/3] kunit: tool: simplify creating LinuxSourceTreeOperations
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: elver@google.com, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	skhan@linuxfoundation.org, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=o5OhYnQd;       spf=pass
 (google.com: domain of 3dcafyggkce8ucrkpgfmxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dCaFYggKCe8UcRkpgfmXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--dlatypov.bounces.google.com;
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

Drop get_source_tree_ops() and just call what used to be
get_source_tree_ops_from_qemu_config() in both cases.

Also rename the functions to have shorter names and add a "_" prefix to
note they're not meant to be used outside this function.

Signed-off-by: Daniel Latypov <dlatypov@google.com>
---
 tools/testing/kunit/kunit_kernel.py | 20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
index 8bc8305ba817..e93f07ac0af1 100644
--- a/tools/testing/kunit/kunit_kernel.py
+++ b/tools/testing/kunit/kunit_kernel.py
@@ -178,19 +178,16 @@ def get_old_kunitconfig_path(build_dir: str) -> str:
 def get_outfile_path(build_dir: str) -> str:
 	return os.path.join(build_dir, OUTFILE_PATH)
 
-def get_source_tree_ops(arch: str, cross_compile: Optional[str]) -> LinuxSourceTreeOperations:
+def _default_qemu_config_path(arch: str) -> str:
 	config_path = os.path.join(QEMU_CONFIGS_DIR, arch + '.py')
-	if arch == 'um':
-		return LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
 	if os.path.isfile(config_path):
-		return get_source_tree_ops_from_qemu_config(config_path, cross_compile)[1]
+		return config_path
 
 	options = [f[:-3] for f in os.listdir(QEMU_CONFIGS_DIR) if f.endswith('.py')]
 	raise ConfigError(arch + ' is not a valid arch, options are ' + str(sorted(options)))
 
-def get_source_tree_ops_from_qemu_config(config_path: str,
-					 cross_compile: Optional[str]) -> Tuple[
-							 str, LinuxSourceTreeOperations]:
+def _get_qemu_ops(config_path: str,
+		  cross_compile: Optional[str]) -> Tuple[str, LinuxSourceTreeOperations]:
 	# The module name/path has very little to do with where the actual file
 	# exists (I learned this through experimentation and could not find it
 	# anywhere in the Python documentation).
@@ -226,11 +223,14 @@ class LinuxSourceTree:
 	      qemu_config_path=None) -> None:
 		signal.signal(signal.SIGINT, self.signal_handler)
 		if qemu_config_path:
-			self._arch, self._ops = get_source_tree_ops_from_qemu_config(
-					qemu_config_path, cross_compile)
+			self._arch, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
 		else:
 			self._arch = 'um' if arch is None else arch
-			self._ops = get_source_tree_ops(self._arch, cross_compile)
+			if self._arch == 'um':
+				self._ops = LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
+			else:
+				qemu_config_path = _default_qemu_config_path(self._arch)
+				_, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
 
 		if kunitconfig_path:
 			if os.path.isdir(kunitconfig_path):
-- 
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518170124.2849497-3-dlatypov%40google.com.
