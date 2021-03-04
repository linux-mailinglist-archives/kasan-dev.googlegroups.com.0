Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNVOQOBAMGQE53D76UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2440632D388
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 13:48:55 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id m71sf7862858lfa.5
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 04:48:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614862134; cv=pass;
        d=google.com; s=arc-20160816;
        b=upM6H5oD4V/cX8JbWeUS1AmeHuLzVpdTcL9P5BKlc41Ckzu1rvMIO2/e1JUljUkAm/
         XONeL07bBaK+IsctlBHb29LSbIH75xl1Iguf4vi1fDydt15gYZ/FX8z8DR6OoBR6Dwtn
         JA/oUsX0DkDnB72++sj6i0Lc/QNN3YIpZd9n9v0EupINFkSIOGddTA7dfLH8chhxBBKT
         bXSqldb6en+IYR7cyri4sMULcki01XXhmwNeDkBEHcrctfwHwy8+UyMZctuTuvXRP22K
         lvRWR8KnE5hcoaw2/cnpWMSMrCVUnLIaN7RXDNpUdT/ZLbyHGwl1aOMlociJ73cigKFB
         O6+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=kytq3xvu3wYTUKMy2WKcbzZG8K49jp9vFhk2q9XRA0M=;
        b=BVe38YxzKc0SO1BshdQfUw3siLd1VROIdqw9sc/iDASD0bvCpFQLcEYkTasPmCRad2
         oBhPCTezrUBU08tWDRk/TM1rbzpbtFCYG8swwnfjEQPrnomVkZy++L2JAeotQXf0CJca
         6Kp1VWuXV063mMqo4OpxvylhuygPyXTbHn61oleC6uWo9NjQvlCwt8ER+Ipms9lj6g84
         n/xrAiqmORbpfDWvbuR4jHXuo0AVkOI5KLHCXzSkKaRmFkn/G4k8cmCopkXQW9Dcczdm
         +okFVh15hNwaZgzBNa9LKfUg8Zvuqv1eR2p7Q333GyiFAFjJIIWoieAQFNZScRd5pJY2
         4PKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXbcH1kP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kytq3xvu3wYTUKMy2WKcbzZG8K49jp9vFhk2q9XRA0M=;
        b=W20IC2oH796ECU4+t4UEG8OPgmR+vMAk/YlXI4A3WgWplpCBqAU+RLhx9eqDvEEg9j
         AMOlOqQFKONHW+xxEC+pHhb2N1XRuimjoPQ0JNFxBYT6gMA+GgEXmMkrQDId4aZDhOYn
         OVd44gW49uWNm35M1l2riWbE87e6SC8cDbT+zV+SG9PNAhrL5B7J8VaqCuMEorSr8dpR
         c0dm1gO7n41Hh23gjH/oqeRCKZXXz3cCFZi1CIR9AQTn+7Q+Us+B85U/xUh8PdnUD70+
         Ot1USWz24kzCtW4H/3ERWAPmDATu2JxLaFZFmgWvH52LxiBIlEaLsmXe+E9bu+pE4J8g
         bWEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kytq3xvu3wYTUKMy2WKcbzZG8K49jp9vFhk2q9XRA0M=;
        b=WhwNmdlfizegaxIcAsdGAUZDoOUtwiMczXU6TYdoA0LFudHvjBMhkN3ZkKtKNA9uKa
         dUVTv7i2nFExpKPRZFUen3MPBesi1ZxO/Zk0Xo/kQZYfQ8znyRE1iJaW/zGG8n7pEseG
         /OALt9yXdEZ8A8qcFU4fjt5r4Fj9dku1nILqeXh86DSpivbBSyqyHfbRSZd3e51Lpvvh
         deUQ86MNis/WYPmos9/H6gZqP76mfJb9nvnWKGqhsZuR8Qp6Hm8TDR0zC5FjtmKHeSWC
         LyBsHZ0NyHWhV4QVDuUDOwwF2cChRGHHnijJ0r01bA+xbcu1kgFKHuzqgm+zKDE3IMuZ
         nviw==
X-Gm-Message-State: AOAM533z22XT7qw9e4tO64FV8lkk3AyjPs7NowGcLILKmYkI/UMbKrJ+
	nS7yXlJE6vCBTdxgoogXMx0=
X-Google-Smtp-Source: ABdhPJzc8a5TrECfA+SD4gn34soUk2fqboC7eiq++46Ota+MdOvgTUxSjY97nTh0+iruMRcvwElE+w==
X-Received: by 2002:a2e:809a:: with SMTP id i26mr2151285ljg.357.1614862134744;
        Thu, 04 Mar 2021 04:48:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls863865lfo.0.gmail; Thu, 04 Mar
 2021 04:48:53 -0800 (PST)
X-Received: by 2002:a19:ec09:: with SMTP id b9mr2285159lfa.0.1614862133546;
        Thu, 04 Mar 2021 04:48:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614862133; cv=none;
        d=google.com; s=arc-20160816;
        b=jZvbu2SrlvheWTyfcyASKz472RUHQp/GjqZASjC/8VRVgxy9geEDJax9jBcaXH6rvU
         ipc2oPEq3qvoEeUSk3XYGG/TMp9OeQBWwzj4NqHqU64jl/xarTh85j9hN0EbGUbUtrwD
         +n2N+kai58vHV3IxbIoT/EgdRNSufI7DEywkovn419mliUvzf3TlvfA1CvsS03RlKtVJ
         +c23p1DC1+zMbpJOvy4mmf8n0jf6AVNa5ppG/SHCk+19scJZMCEICcGqqjwq8QAe06+o
         NEm/uHcJ0pKVdqAe4Gn+YE/3S7DS73pi97V8EwW8fP+NVvgYWZvcNMnMd8QGVGbwudUo
         Iw/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tLUSBdXqsZoskjTYTdXu1BqIlUPP/WrZ7mFGxUMCU0I=;
        b=YX9uoVsEUHREjXyAZYEA0W3K54Gv5nlA7fkahGCbocaqUvdnheDAL3tgGnMlNrU3I6
         M1VIl47V4DBGHij5ac6ftRW3Xqu0jreP0Lc13swNbsOIf4Tm4n4Wf8Kn3SC1ClCGYdlr
         vJVOg0mHwmDqaXVdh4QRio5PBHyozOkGXuffOGsbgiK1QDewSlswYMS8U2M74y3k84Qv
         BCsBcTXD6LLGpYc41HZq44p04BSdZLEZX4SgtGGwiGeX99Hj5Kvi9stcVRJjg3uxhhNo
         Cea38KJd4v+5lOkC3U5+zkahDTZ//+FGJBYZmreZcGQkbFtjd1UBIsQ8GAabFpXruOlE
         wqOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXbcH1kP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id z2si1037860ljm.0.2021.03.04.04.48.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 04:48:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id m7so1233147wmq.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 04:48:53 -0800 (PST)
X-Received: by 2002:a7b:cf2f:: with SMTP id m15mr3718425wmg.177.1614862132881;
        Thu, 04 Mar 2021 04:48:52 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:e426:34b7:f237:f8d3])
        by smtp.gmail.com with ESMTPSA id z21sm9778125wma.29.2021.03.04.04.48.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Mar 2021 04:48:52 -0800 (PST)
Date: Thu, 4 Mar 2021 13:48:39 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Dmitry Vyukov <dvyukov@google.com>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
Message-ID: <YEDXJ5JNkgvDFehc@elver.google.com>
References: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mXbcH1kP;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Thu, Mar 04, 2021 at 12:48PM +0100, Christophe Leroy wrote:
> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
> > On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
> > <christophe.leroy@csgroup.eu> wrote:
> > > Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
> > > >=20
> > > > Somewhat tangentially, I also note that e.g. show_regs(regs) (which
> > > > was printed along the KFENCE report above) didn't include the top
> > > > frame in the "Call Trace", so this assumption is definitely not
> > > > isolated to KFENCE.
> > > >=20
> > >=20
> > > Now, I have tested PPC64 (with the patch I sent yesterday to modify s=
ave_stack_trace_regs()
> > > applied), and I get many failures. Any idea ?
> > >=20
> > > [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_f=
ree+0x2e4/0x530
> > > [   17.654379][   T58]
> > > [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence-=
#77):
> > > [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
> > > [   17.655775][   T58]  .__slab_free+0x320/0x5a0
> > > [   17.656039][   T58]  .test_double_free+0xe0/0x198
> > > [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
> > > [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> > > [   17.657161][   T58]  .kthread+0x18c/0x1a0
> > > [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
> > > [   17.659869][   T58]
[...]
> >=20
> > Looks like something is prepending '.' to function names. We expect
> > the function name to appear as-is, e.g. "kfence_guarded_free",
> > "test_double_free", etc.
> >=20
> > Is there something special on ppc64, where the '.' is some convention?
> >=20
>=20
> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64a=
bi.html#FUNC-DES
>=20
> Also see commit https://github.com/linuxppc/linux/commit/02424d896

Thanks -- could you try the below patch? You'll need to define
ARCH_FUNC_PREFIX accordingly.

We think, since there are only very few architectures that add a prefix,
requiring <asm/kfence.h> to define something like ARCH_FUNC_PREFIX is
the simplest option. Let me know if this works for you.

There an alternative option, which is to dynamically figure out the
prefix, but if this simpler option is fine with you, we'd prefer it.

Thanks,
-- Marco

------ >8 ------

From d118080eb9552073f5dcf1f86198f3d86d5ea850 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Thu, 4 Mar 2021 13:15:51 +0100
Subject: [PATCH] kfence: fix reports if constant function prefixes exist

Some architectures prefix all functions with a constant string ('.' on
ppc64). Add ARCH_FUNC_PREFIX, which may optionally be defined in
<asm/kfence.h>, so that get_stack_skipnr() can work properly.

Link: https://lkml.kernel.org/r/f036c53d-7e81-763c-47f4-6024c6c5f058@csgrou=
p.eu
Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/report.c | 18 ++++++++++++------
 1 file changed, 12 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 519f037720f5..e3f71451ad9e 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -20,6 +20,11 @@
=20
 #include "kfence.h"
=20
+/* May be overridden by <asm/kfence.h>. */
+#ifndef ARCH_FUNC_PREFIX
+#define ARCH_FUNC_PREFIX ""
+#endif
+
 extern bool no_hash_pointers;
=20
 /* Helper function to either print to a seq_file or to console. */
@@ -67,8 +72,9 @@ static int get_stack_skipnr(const unsigned long stack_ent=
ries[], int num_entries
 	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
 		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[ski=
pnr]);
=20
-		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") |=
|
-		    !strncmp(buf, "__slab_free", len)) {
+		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
+		    !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
 			/*
 			 * In case of tail calls from any of the below
 			 * to any of the above.
@@ -77,10 +83,10 @@ static int get_stack_skipnr(const unsigned long stack_e=
ntries[], int num_entries
 		}
=20
 		/* Also the *_bulk() variants by only checking prefixes. */
-		if (str_has_prefix(buf, "kfree") ||
-		    str_has_prefix(buf, "kmem_cache_free") ||
-		    str_has_prefix(buf, "__kmalloc") ||
-		    str_has_prefix(buf, "kmem_cache_alloc"))
+		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
 			goto found;
 	}
 	if (fallback < num_entries)
--=20
2.30.1.766.gb4fecdf3b7-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YEDXJ5JNkgvDFehc%40elver.google.com.
