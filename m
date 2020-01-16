Return-Path: <kasan-dev+bncBDQ27FVWWUFRBF4EQDYQKGQEC4XJWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F0D2613D444
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 07:26:32 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id d17sf7172503ybl.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 22:26:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579155992; cv=pass;
        d=google.com; s=arc-20160816;
        b=ExJA5vlRlMjAYZnQjiJhNfAztnvdXTjjAQUGuGeJBfS1ztrLJQsr/TXk8TM3nYG1rg
         K3RmR8FzuLDaPVeel82dcOL381x3hLJfBI3vfwt5OB0ywzbD5PX862jbouSSBNtfze/f
         WlYJ8gLGwbvaCdYiaEmNMRUklsllAkE2uagdwuykPE/3YLvedtogK1UAdoAFcPcBmODY
         05QGt3Sw5H61FY/mJgRP6rSq4GClSCCTr2t2XDm3Ipd9xjMypekSDSltdw50dtMGHP8d
         w+BCfmxHpjpMHs5BHPi8DjGeIwMNfe99Ih/TdeeoqmNnuavUt8xfrmacIUWu2gM4aYWB
         63eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=se5UFcu6QcdH5w69OIh4bVKMszSBTz5ZTfhi1Bmz+hw=;
        b=z9SLkWYzYqqjLseTMG8fH2GP7UZw0p5hkMsCALsDB/wk7suVY/3CKXy2roxcb01Fe8
         NLh6y47CQMKQFiPOWexylV5wbw+fACzx/8VSr6tt6E9KODIbaUwcWQ/sixWpiCmvY8c6
         WBU2VLzBNAPqVvW4TZ6+W5lJKqLKyU14putEdoNrH7FhV1puj36A9fuGPjxJ9+ZBNQjp
         MfgBU4kbUfG9F7M5gpaX9HsNubzSNzJlmiYDBZKUMg5BJ3YxFopayLN+haZVRfWwQMmi
         jFXvCVy8csMh4I/nzXxk3hzB7Cne8ZNNhOrG7gZMAS1dBeOrlJs4pJKsBl31bJ4yI/VL
         k7YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oNmexNcV;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=se5UFcu6QcdH5w69OIh4bVKMszSBTz5ZTfhi1Bmz+hw=;
        b=sp53ZrVUX5b6eR9OH1YzvQahLyXu2mQQcH6SFDxwVanY4qnXxQgilbx7NffVF5J1IR
         Ngxtsh6/KAW0uJgFgpyo09B1KaCmggTDFDp8KDqPAFt9js7fjlB6REESDM3Sipt9DklR
         8vL7327KCn9qiWYJI2X8ojxBgVC9RYzICTRaDc5b/ViJJ65bYNrB33pQ6BHu/NUfRTTR
         2DL1ZWoFX+WSCBd0eIOe8vWOVzXOHt11+CDzp7vmI/kdPw0GyEOkgNtzy730nBRMHMCY
         MM0ebFmd0QnukdSfmq5+ByiMaDXm1q392OXXEA98v39YvGy33r22aLHlHxwEio8oV3ku
         qedw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=se5UFcu6QcdH5w69OIh4bVKMszSBTz5ZTfhi1Bmz+hw=;
        b=MicYH3f1K8doOfCbB25ZTlvCuNumGYaHx0z0jmKKujR9YFIvQxeeY8738C7uqbzsVf
         HfUnD1MepeXKk7JvaiVfj7mov8NsBA48Dn/mHvEMMD2svRaFK6IknW3WwLl0gld9WY+8
         h3/UdfAofuAq75FMu04BIMblhGgF4ZIo7UhrRxJBFFT6H27CdUnnOAyLfEVHoWXOMvAz
         vSdbO0cvCFWs4m1dSFhFp+l2tLSwAfcSVgUrM56Ts6r7q2ERRhIDuAGvGpeMMX9P2FJ7
         VFyMrJCWMa2YIXVVpsfcxVFbxqX16EwWwsb2Slk4hwhELHWCmFe9aEiXAsnJoHScLrLJ
         4+QQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUV96SlIk0oVdeAALOVkcLgenuctEiVzzRr46beoeLb9IrhqJkx
	G5pMD52zvcEzshAyNOj8vD4=
X-Google-Smtp-Source: APXvYqwLcYn1H7Gk/zCZ+cwDpOcOAxEsV5G3pfWoZO+7Fh+nPmGB9/dJOdYEvYZaOgLKQA8tAHSpwQ==
X-Received: by 2002:a0d:d68d:: with SMTP id y135mr24609125ywd.310.1579155991976;
        Wed, 15 Jan 2020 22:26:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9b07:: with SMTP id s7ls3409298ywg.14.gmail; Wed, 15 Jan
 2020 22:26:31 -0800 (PST)
X-Received: by 2002:a0d:cdc5:: with SMTP id p188mr26325257ywd.313.1579155991666;
        Wed, 15 Jan 2020 22:26:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579155991; cv=none;
        d=google.com; s=arc-20160816;
        b=k/7i9mM85+3iPjAaWEMF0u87uBpGY2HwUTCw9EQ81v4NqC6XGALLyraEFqlezx95Ug
         muLc5mEn9rnFHqRTXaKQjkVHfVyQnvVKnwhOhtxXT6tnbBoM1Huf9ikDgvVRIfufFNsa
         FdDAjOWoz9new4Nun1dntYaumoQiNekDZFyNQq9V/w4DeC+E7JdU8zxTnezzH/w/0+uP
         C9uffMpKdhJgu/+dwN8fEdhIgiCzSQPg+4uKIDfhtrnTxl6bMsPCd8kPXqcA7k51WAPM
         rmaZf6fqaXXBxV0YZ3ml3OZzqnJ1yxbjO5QA3jAqM84bzWzBNmQMUGSkgdloIAB0RIy9
         0A4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jgsZ87j9zhFzITBOLkD7Zx7YPDB2pB7wEvRvkLTLK58=;
        b=PEqxu24d9V8zNdTCw5UxPB8NoGlY+2RFA/X1PfBFdpVHFi7LN8XN8zzehyRBVffz5p
         YlRppeozx1PPnTcPuz8+XI5nsiLqRYBZu37DApQeDXxesQ85khB85hByX6PUkIQotDA/
         R/fyvd4xj3bQTnJe3I/cGw4OqPtpqWGnWCNGm7QUYcsXTPzwdE/K/Am3muWm86nNAwih
         I+BAzNYEHjRT+Zm4sL6zrgd+VSyzeWALCYaJ6jfzpQfBr8oviGPbNW4NliF9yrmIt9SC
         JLQ56JPwTv4zhpVfsfUrdCi5YppcwuvPRZxvCGGUVdXbldSH4m+y+zpHqnYgWnRDpNRu
         Qm1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oNmexNcV;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id s131si410953ybc.0.2020.01.15.22.26.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 22:26:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id c23so7902214plz.4
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 22:26:31 -0800 (PST)
X-Received: by 2002:a17:902:9307:: with SMTP id bc7mr29877693plb.338.1579155990819;
        Wed, 15 Jan 2020 22:26:30 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id c68sm24184007pfc.156.2020.01.15.22.26.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 22:26:30 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 0/3] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
Date: Thu, 16 Jan 2020 17:26:22 +1100
Message-Id: <20200116062625.32692-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=oNmexNcV;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen. I have observed this on x86 and powerpc.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the
operands. However, these functions often directly invoke __builtin_foo()
once they have performed the fortify check.

This breaks things in 2 ways:

 - the three function calls are technically dead code, and can be
   eliminated. When __builtin_ versions are used, the compiler can detect
   this.

 - Using __builtins may bypass KASAN checks if the compiler decides to
   inline it's own implementation as sequence of instructions, rather than
   emit a function call that goes out to a KASAN-instrumented
   implementation.

The patches address each reason in turn. Finally, test_memcmp used a
stack array without explicit initialisation, which can sometimes break
too, so fix that up.

v2: - some cleanups, don't mess with arch code as I missed some wrinkles.
    - add stack array init (patch 3)

Daniel Axtens (3):
  kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
  string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
  kasan: initialise array in kasan_memcmp test

 include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
 lib/test_kasan.c       | 32 +++++++++++++---------
 2 files changed, 68 insertions(+), 24 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116062625.32692-1-dja%40axtens.net.
