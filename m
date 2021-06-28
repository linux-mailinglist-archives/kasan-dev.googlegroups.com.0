Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUV5CDAMGQE75CJJ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A8263B67EE
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 19:46:14 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id p20-20020a1709064994b02903cd421d7803sf4672907eju.22
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 10:46:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624902374; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJyUOCMbSzhpih2f6cTcYGSAIsbuFF5Ai5ju/+RUWOxy73z6kz1hKYP1AUxdINvznQ
         ldisnVTmciL/xb3gPoxH+LJWmfsE1Kef/9XLf35TaQldyT0oYkSLYKlkgdzPbwyp9wa1
         TbVtxt290SvalJKeHKEQUM0wW3tDTTOxFwgiYTfe5AbR0BQGuBnL7RdcXtuU12Ve33z/
         6+Rl7MqfdwiuarZF+1+EoS/UjVtaHG19jBCHBg0m3pSA5L1KyCfXS8Z//9jB/qAl/mDG
         i5kryyutmRivyF0UhJR6R5MmDm6a50g64xCB8lVXpR0C1V3fR3AHpXyQQT34BWiMEOm4
         j/GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=J9GYqdBjb0Ry5CbC/oHkHu2mnIZnjVwCvSu1mFPCP1M=;
        b=MoB4JeZiI2WiJVj67UK/dHE0HuvvkRHHV0MVV3U0S9j2so1Up48ODAjpSwGdvC7iPR
         Hyku2q54H2eJromJUUuq4I0zy0vNH359RL97Z09TAuAsCJbYOrwXsGjBKSHmjtYFI8yk
         /ZDh+u7mW23mc9CQdNIHOn1iem6ny0AXDR8SprfEzrfiqDGORN8FQALFeE9MhT5Rv2Y0
         BNCR0xVqenojE6DfyuYmGUsW2CMGGzxBR9wBPHd+uMZm1rQEN3ilHi/ziJyWJCuFtBp/
         xOjtwYKRFJrGZYyXbQW4Z0/MA1Fx9mnc/tgKvfYVILdp3jJ7VSiqzU/TpxoFRL2SlK/o
         sWIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d2kEOl8G;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J9GYqdBjb0Ry5CbC/oHkHu2mnIZnjVwCvSu1mFPCP1M=;
        b=XcINl+OXLhQ29UJcnOXouz3BMVJXbABx7zhRqBBKIRKXIKH8aHgWr20FQusbPj8z9C
         lQqqkwWo6Zs6ewQth3PQp+cba7Jrv4GiUnkoqv09/Wzdx/EpBNGJ9TjDxRKNdT5gTKu3
         F4QKq0vzkg4cIWC0X4hK4rBAI4mJhIRkYdkswf51MZz5xL3LLdAHP0tN5wEBILm+RIRD
         fC/+ZoOk9oDb8A6oZXQHACU5JZPnh+nFe14fQ/TyV2miXTHsPKLU1clypxbDr2Q2Giup
         Bs6+FAY0V0h9rwCIV/YXIrc1Q/EIG952WDrD2bYewAkfIjOaCziKcWAu3xYFGT0NPhTD
         PzcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J9GYqdBjb0Ry5CbC/oHkHu2mnIZnjVwCvSu1mFPCP1M=;
        b=pFcemmSUw7owZfQX8ZGDSt5d/6AS+g1mrztvPO1/e3FD+Kd90BX6nMCCuP43GEoujY
         U7iOa5YZI3gxy+ZfkJ7Eb10gfmJDlY1sR9Fikaei2E/3HCoChzvucdchw6F1vGg/XRsA
         YoeMSRtgfnat4lElQ4edJKt8D4qteshP9jFpUkKZiQS16RmCdxp+8bUPFo0K4RRlmaWb
         RR1T7yUZAOJc+oxazy9c2njgEmjS5K4V4B+7QvlDhvMxlgzlINeYcOi5BcnYlxnir1cn
         LHMuEJOuae8iUOE1WoXL5Uwr5wZNiicYLcfJmJF4nkSdfXnyGJTPWHfL9gXk3TRpCaII
         w4UQ==
X-Gm-Message-State: AOAM531VRX9AmxMWkVMc/wubLD8lu4qofs0JjSFYePx3KL/hrcYRwHVM
	w67y1jvbx1KA58UtFddKPwc=
X-Google-Smtp-Source: ABdhPJy4JuzV2QTfpgZzR9VbOh5nmM/W54wsyWnNyQYsLeFn/MMvMKqkrHObxRZuCQGFRu6B2drKbA==
X-Received: by 2002:a17:906:1487:: with SMTP id x7mr25242845ejc.456.1624902374314;
        Mon, 28 Jun 2021 10:46:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c14b:: with SMTP id r11ls1624694edp.3.gmail; Mon, 28 Jun
 2021 10:46:13 -0700 (PDT)
X-Received: by 2002:aa7:db52:: with SMTP id n18mr34487133edt.170.1624902373245;
        Mon, 28 Jun 2021 10:46:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624902373; cv=none;
        d=google.com; s=arc-20160816;
        b=WajyMYt7i5yrvnQ/zwHx/ekCEryXDCHK5+GE7zeWQMVFZdNlyJ7DSNsDaRhEHoV3kD
         2MVO3K8zU+GPqthvcRR4g1oZ7gO7oTENMmLAHg/wRfkLnMbO1r4w1iB8pI4s+gWAHfg4
         fA6NHekK59CvyaNpU0zjlRdSngE/gdf7dqUlsZfGHiVzGK5nPhNpPCW46QdhGIbSu9US
         174W0TbDBXmDQTct8UPRieP0N0ppma6vAWncvrokmtom1IBwTyJ3lB+ZYzmO4vON07/+
         q5gCwFqfD7ZBWQr2OWuG6lZI66md57vOH2k47QOIGUxAXOmQ2R9BK1SjAPc/fvoD8tk9
         +VIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ir4xkRBihdN+IRSqF+wlm+S2OyFvEnWSnx+5T/4aFVo=;
        b=C6m4GE57oQpFDMPWw6/1hb3vjPGb2TK+3ftGJC4L9RW1x/dUticyE/qEPmfb1tIgvE
         F581CEq9RYgYQEk7Jcig5LNyj+J4HZwl+ve87jtl/1LcDit6iCXeP/rf+rdTyrFmpr/7
         x1JG8Ux7Jf9ihhKiOb51iCBNZkZeK3EzjTUEyaXn9jegIWPgTOzTbhmF6sUIsmXRn1j+
         68bsA/GCL5iGrlnTx1QYRYKHMJzo9n5OG21NBmbNvd/6JjcRTcZvylEfhCb3mDvsGbqD
         sHqBdyaw7YilIyWu1eisGST/EW5fHdJUhXeWC5CIUy6CGrOn56gbk2WtPxJ7IkFTyU/f
         TLZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d2kEOl8G;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id u19si878343edo.4.2021.06.28.10.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jun 2021 10:46:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id u8so8987970wrq.8
        for <kasan-dev@googlegroups.com>; Mon, 28 Jun 2021 10:46:13 -0700 (PDT)
X-Received: by 2002:a5d:6a01:: with SMTP id m1mr29104296wru.363.1624902372835;
        Mon, 28 Jun 2021 10:46:12 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:6136:a356:cc5c:f9ac])
        by smtp.gmail.com with ESMTPSA id o26sm14034880wmr.29.2021.06.28.10.46.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jun 2021 10:46:12 -0700 (PDT)
Date: Mon, 28 Jun 2021 19:46:06 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <YNoK3gss3nFxbpjB@elver.google.com>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <YNnynlQRxr9D3NJJ@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YNnynlQRxr9D3NJJ@cork>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d2kEOl8G;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Jun 28, 2021 at 09:02AM -0700, 'J=C3=B6rn Engel' via kasan-dev wrot=
e:
> We found another bug via kfence.  This one is a bit annoying, the object
> in question is refcounted and it appears we got the refcount wrong and
> freed it too early.  So kfence removed one layer of the onion, but there
> is more to be done before we have a fix.

Nice.

> What would have been useful in the investigation would be a timestamp
> when the object was freed.  With that we could sift through the logfile
> and check if we get interesting loglines around that time.  In fact,
> both time and CPU would be useful details to get.  Probably more useful
> than the PID, at least in this particular case.
>=20
> Does that sound like a reasonable thing?  Has it maybe already been
> done?

How about the below?

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Mon, 28 Jun 2021 19:17:12 +0200
Subject: [PATCH] kfence: show cpu and timestamp in alloc/free info

Record cpu and timestamp on allocations and frees, and show them in
reports. Upon an error, this can help correlate earlier messages in the
kernel log via allocation and free timestamps.

Suggested-by: Joern Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 99 ++++++++++++++++--------------
 mm/kfence/core.c                   |  3 +
 mm/kfence/kfence.h                 |  2 +
 mm/kfence/report.c                 | 19 ++++--
 4 files changed, 72 insertions(+), 51 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/k=
fence.rst
index fdf04e741ea5..0b9c6a441656 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -65,25 +65,27 @@ Error reports
 A typical out-of-bounds access looks like this::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa3/0x22b
+    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa6/0x234
=20
-    Out-of-bounds read at 0xffffffffb672efff (1B left of kfence-#17):
-     test_out_of_bounds_read+0xa3/0x22b
-     kunit_try_run_case+0x51/0x85
+    Out-of-bounds read at 0xffff8c3f2e291fff (1B left of kfence-#72):
+     test_out_of_bounds_read+0xa6/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=3D32, cache=3D=
kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
-     test_out_of_bounds_read+0x98/0x22b
-     kunit_try_run_case+0x51/0x85
+    kfence-#72: 0xffff8c3f2e292000-0xffff8c3f2e29201f, size=3D32, cache=3D=
kmalloc-32
+
+    allocated by task 484 on cpu 0 at 32.919330s:
+     test_alloc+0xfe/0x738
+     test_out_of_bounds_read+0x9b/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 0=
4/01/2014
+    CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 0=
4/01/2014
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
 The header of the report provides a short summary of the function involved=
 in
@@ -96,30 +98,32 @@ Use-after-free accesses are reported as::
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
     BUG: KFENCE: use-after-free read in test_use_after_free_read+0xb3/0x14=
3
=20
-    Use-after-free read at 0xffffffffb673dfe0 (in kfence-#24):
+    Use-after-free read at 0xffff8c3f2e2a0000 (in kfence-#79):
      test_use_after_free_read+0xb3/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=3D32, cache=3D=
kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#79: 0xffff8c3f2e2a0000-0xffff8c3f2e2a001f, size=3D32, cache=3D=
kmalloc-32
+
+    allocated by task 488 on cpu 2 at 33.871326s:
+     test_alloc+0xfe/0x738
      test_use_after_free_read+0x76/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    freed by task 507:
+    freed by task 488 on cpu 2 at 33.871358s:
      test_use_after_free_read+0xa8/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.=
0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 0=
4/01/2014
+    CPU: 2 PID: 488 Comm: kunit_try_catch Tainted: G    B             5.13=
.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 0=
4/01/2014
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
 KFENCE also reports on invalid frees, such as double-frees::
@@ -127,30 +131,32 @@ KFENCE also reports on invalid frees, such as double-=
frees::
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
     BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
=20
-    Invalid free of 0xffffffffb6741000:
+    Invalid free of 0xffff8c3f2e2a4000 (in kfence-#81):
      test_double_free+0xdc/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=3D32, cache=3D=
kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#81: 0xffff8c3f2e2a4000-0xffff8c3f2e2a401f, size=3D32, cache=3D=
kmalloc-32
+
+    allocated by task 490 on cpu 1 at 34.175321s:
+     test_alloc+0xfe/0x738
      test_double_free+0x76/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    freed by task 507:
+    freed by task 490 on cpu 1 at 34.175348s:
      test_double_free+0xa8/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.=
0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 0=
4/01/2014
+    CPU: 1 PID: 490 Comm: kunit_try_catch Tainted: G    B             5.13=
.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 0=
4/01/2014
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
 KFENCE also uses pattern-based redzones on the other side of an object's g=
uard
@@ -160,25 +166,28 @@ These are reported on frees::
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
     BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/=
0x184
=20
-    Corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ] (in kfence=
-#69):
+    Corrupted memory at 0xffff8c3f2e33aff9 [ 0xac . . . . . . ] (in kfence=
-#156):
      test_kmalloc_aligned_oob_write+0xef/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=3D73, cache=3D=
kmalloc-96] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#156: 0xffff8c3f2e33afb0-0xffff8c3f2e33aff8, size=3D73, cache=
=3Dkmalloc-96
+
+    allocated by task 502 on cpu 7 at 42.159302s:
+     test_alloc+0xfe/0x738
      test_kmalloc_aligned_oob_write+0x57/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
=20
-    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.=
0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 0=
4/01/2014
+    CPU: 7 PID: 502 Comm: kunit_try_catch Tainted: G    B             5.13=
.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 0=
4/01/2014
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
+
 For such errors, the address where the corruption occurred as well as the
 invalidly written bytes (offset from the address) are shown; in this
 representation, '.' denote untouched bytes. In the example above ``0xac`` =
is
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index d7666ace9d2e..0fd7a122e1a1 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -20,6 +20,7 @@
 #include <linux/moduleparam.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/sched/clock.h>
 #include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
@@ -196,6 +197,8 @@ static noinline void metadata_update_state(struct kfenc=
e_metadata *meta,
 	 */
 	track->num_stack_entries =3D stack_trace_save(track->stack_entries, KFENC=
E_STACK_DEPTH, 1);
 	track->pid =3D task_pid_nr(current);
+	track->cpu =3D raw_smp_processor_id();
+	track->ts_nsec =3D local_clock(); /* Same source as printk timestamps. */
=20
 	/*
 	 * Pairs with READ_ONCE() in
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 24065321ff8a..c1f23c61e5f9 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -36,6 +36,8 @@ enum kfence_object_state {
 /* Alloc/free tracking information. */
 struct kfence_track {
 	pid_t pid;
+	int cpu;
+	u64 ts_nsec;
 	int num_stack_entries;
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 };
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 2a319c21c939..d1daabdc9188 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -9,6 +9,7 @@
=20
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
+#include <linux/math.h>
 #include <linux/printk.h>
 #include <linux/sched/debug.h>
 #include <linux/seq_file.h>
@@ -100,6 +101,13 @@ static void kfence_print_stack(struct seq_file *seq, c=
onst struct kfence_metadat
 			       bool show_alloc)
 {
 	const struct kfence_track *track =3D show_alloc ? &meta->alloc_track : &m=
eta->free_track;
+	u64 ts_sec =3D track->ts_nsec;
+	unsigned long rem_nsec =3D do_div(ts_sec, NSEC_PER_SEC);
+
+	/* Timestamp matches printk timestamp format. */
+	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+		       show_alloc ? "allocated" : "freed", meta->alloc_track.pid,
+		       meta->alloc_track.cpu, (unsigned long)ts_sec, rem_nsec / 1000);
=20
 	if (track->num_stack_entries) {
 		/* Skip allocation/free internals stack. */
@@ -126,15 +134,14 @@ void kfence_print_object(struct seq_file *seq, const =
struct kfence_metadata *met
 		return;
 	}
=20
-	seq_con_printf(seq,
-		       "kfence-#%td [0x%p-0x%p"
-		       ", size=3D%d, cache=3D%s] allocated by task %d:\n",
-		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1)=
, size,
-		       (cache && cache->name) ? cache->name : "<destroyed>", meta->alloc=
_track.pid);
+	seq_con_printf(seq, "kfence-#%td: 0x%p-0x%p, size=3D%d, cache=3D%s\n\n",
+		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1)=
,
+		       size, (cache && cache->name) ? cache->name : "<destroyed>");
+
 	kfence_print_stack(seq, meta, true);
=20
 	if (meta->state =3D=3D KFENCE_OBJECT_FREED) {
-		seq_con_printf(seq, "\nfreed by task %d:\n", meta->free_track.pid);
+		seq_con_printf(seq, "\n");
 		kfence_print_stack(seq, meta, false);
 	}
 }
--=20
2.32.0.93.g670b81a890-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YNoK3gss3nFxbpjB%40elver.google.com.
