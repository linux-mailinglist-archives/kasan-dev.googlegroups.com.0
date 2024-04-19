Return-Path: <kasan-dev+bncBDYZHQ6J7ENRBRN4RGYQMGQE4NCX7PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1817F8AAE14
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 14:06:31 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-36b14592349sf156425ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Apr 2024 05:06:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713528390; cv=pass;
        d=google.com; s=arc-20160816;
        b=GV+3BJ6kwHfo/ByLQtLNKwSfZtOrcD9KknPecro1uDgtAjlm7JAYMCbMBCBwThLHEi
         ClM9f2kUrVJ5HbZYgz3hQayiRO/prrJiOBxFcTvnbz3e2PLos5CqMkF0McnQDpWOtQCN
         mRPm3fx0AlkYMM8U8dbzfbAdfETZLhOnjF1FtII53iTr9cZR6gC7r3Cngiw0XpxJ3Rwb
         1rb29kk8vYejEnCimryj1H2HmceGzmw86U2OA5TZFveLCEmjuzy3axGHzQb2zgxjh1hA
         yyYQ0ZVDoGCZn5ZICCkVXRftCYKp9kJBPoWXoZL/UJucMhX/vRMKLhKvyX2u5X17ku7T
         zXfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=/jxJZ9/drayqsjmo4yYsSgOiIYRN+jHMPvV+GYKuC6s=;
        fh=fmNxLMLgU+DlAV0xrEpetwZwMvUlsPoyiymmSM9vq70=;
        b=uxaxz50NxVAf0H0bBOVWP8zbrP+O2q/UJr1lOOGnoAwHW4QeXWIifOooPGLXzzYXR+
         hzgouSbNBT3mpoiJ7rHS2nH1P7jqFI6fQHbWF7Xul4EFpW4vb6WGQGAGgI3TEKBCZI0s
         EOKSXfD4IDI3lZ0MDUwByd1tOmtljOYf+qC3h32O2+eZCkosi7genmpL7UL5CKatC7uk
         gECM9hCKIzGVJ67UaOZc00vR4wMAjSMSCWB4Re4QSkVeBPaHiJHPhIyYbdMUa5Luwgsu
         c5cbt9Z7Hgec2b/LzVBr8IwoOu6NmcRFBkkpzYrw4Gcu+KAkyDmVHidDuymQsOFUTauT
         o16g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UKpSSIcu;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713528390; x=1714133190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/jxJZ9/drayqsjmo4yYsSgOiIYRN+jHMPvV+GYKuC6s=;
        b=lIXvBR3Ut+lIJfjGr34yz0XoZ1ZKsOD+D54YIbZFKhMr8qmVpe+KYVyipXgKm6oLNv
         25knf29MLP8vobQyO7vco904aQ67YWDsCfHsj5RPh8pZXN6gd9fShPm0IeczV5x52ITs
         lFAvwpN3zA23WKvG7GVlo2E1e10D7u5vXNgfZfKIBdMGVxu+K8oKeEOpzyATa7u6irPN
         LKRbcCNw2XT7pwWhYmvUtcF3BLsca2FOm1JyStcwX8JfDKtGm8Cfqw52CTPLgvv+Vl9g
         vZeL9f00MJiNcj1i/HkRnF0YwcDF9PEXKJbK1JKZzkBOkDcEh4NAV/M0HR5TSJdO7R8z
         gRtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713528390; x=1714133190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/jxJZ9/drayqsjmo4yYsSgOiIYRN+jHMPvV+GYKuC6s=;
        b=fD70UuHoBTjcwcaXfDTqehSwk2syZG7ks9+hDyLIPflwS9ICkHJk3Y6WhiVai97hQi
         t4F7QFmSBJeXpGNEdky1z1Zcpc2EWIQu9L7U77DEpmQe7HfMryv3ax+neHkO4WElOBaY
         FR0On/m5H+vj2L5MAmfR5hY0Q/YnysJ9idyAlPIsoZLIezSmUXsmMIuM5zIzk6VE3BC0
         Ot94VXBsd18rAaPokxn2TZaPdjK/5TqGWDpkOMx8/9OZ18gjtJBxfUKL2XD8ahFJEVkS
         3GgEyJN+eUj5STk5lWd34iTGpOnEXQGrzjaBYb9X5yftsIhopZxFaIe51WX7Xn7bzMbz
         Ypqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWO2cbJg+E0gNsncrEB3AHv0U1JPX0P4npmWLv6pExRydFiTOghcHUcm0JY5dy1YI9RY2iUNfnpMKoEukGESCVeW/DFsa1Uqw==
X-Gm-Message-State: AOJu0YzkuVAth+iv9bu8a326cHUQ3mdz2dpkWpbsr9L0NtNCZrRnqy7p
	+5V0kYNOMeiEGBg4uHD13XKp/pww9Qo6LTasq+O5v5Wiiz6bIhXP
X-Google-Smtp-Source: AGHT+IGBl3llksfqULnzRRrNlQYH+LB+gSDk/W804WHY06iz7BPowpVH6OAvChdDTQ5C1WlJWNUcQQ==
X-Received: by 2002:a92:c852:0:b0:36a:f75:14ac with SMTP id b18-20020a92c852000000b0036a0f7514acmr172052ilq.27.1713528389640;
        Fri, 19 Apr 2024 05:06:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d94:b0:368:b117:a4ac with SMTP id
 e9e14a558f8ab-36bfbb22e38ls890625ab.2.-pod-prod-01-us; Fri, 19 Apr 2024
 05:06:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXZ83HmbHtgsWewUpd4A3Inh9CdrmwoKgEJq+3L/E3rlsr2VfIrRlQ1sK8/H8gE4wEvDTnsD/yGFVoDRGT/iOWao/cW51FqaD/3Q==
X-Received: by 2002:a05:6602:6414:b0:7d5:cbb4:f4ed with SMTP id gn20-20020a056602641400b007d5cbb4f4edmr2372186iob.11.1713528388465;
        Fri, 19 Apr 2024 05:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713528388; cv=none;
        d=google.com; s=arc-20160816;
        b=JvOFAcDkp+Ati7YkvgbmGalUP//cU7oBCo6Qb5ZDB9gatXV+8Scfg+MDXljrkOPwG9
         Anvk+dPcao4uP/rP5sKBd6q2RFb7bqYr8KxC+PWPrxji8jtVeK2xo26S8DpMo2yP5Zr0
         o8iPsawuMIV0SdHeDg+Nu/v2b12qFp9XaHTi2jVqwMZhNboFhzh5w8p2xTXGxpjXITwm
         gRYAOhX1+4ilQWX2+9+nk0aDiyqBEj48ps1GNaQHh5+D4qGj8iVlxIqEv2zn/2pRoer0
         e6lY8Har3cHhMxuolD4+a0kfyfsAo7rqEKPxsu9dRTlF5v5yKFC8kfka3i5yyuVeURi3
         F5pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NmaOg63ERdXMl1XMaltCX8llTPAm3e6tKfBbcHBAzFU=;
        fh=0qaKjnSCVtHklYw1UjLlIYInIlEiwp7ZPQA84VpiTyg=;
        b=jttxLV8NE/AmA+98iMGlAhxPWBvA7ou2fkGdQl0fyYNf9uFF0s8SIy2pnhZiQzEb3P
         P/gHSQDCi+loOkVwrDJiMSTSPGaEE5P1cMJAN5rVmym6q2WjW847jghjF3R5yRiIsmKI
         KgQIkwHLK6PFIV3ajuyZQbaFMzozwlslKTtM0PsrcaYrib7gs/8uhKlqwkW/qsv3anHy
         PpTmG7bSm6/O+NSuMc4oPIC8eabH7jpjaSG6b61fLZ1QKKH7qZV8sft5HhrGAe6c3vSv
         7A79pihAgW1U6pcRnf3ht+nGi5AwZ/Y8HMWBTORrih/m8KaqfyL1AkpjERtJq6Y5xiZg
         jt0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UKpSSIcu;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a6-20020a6bca06000000b007da1efe387csi428520iog.1.2024.04.19.05.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Apr 2024 05:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yb1-f199.google.com (mail-yb1-f199.google.com
 [209.85.219.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-648-2vIJjBAgObGZP6sseqQCcQ-1; Fri, 19 Apr 2024 08:06:26 -0400
X-MC-Unique: 2vIJjBAgObGZP6sseqQCcQ-1
Received: by mail-yb1-f199.google.com with SMTP id 3f1490d57ef6-ddaf2f115f2so3345552276.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Apr 2024 05:06:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUEW3geKCkYLPcaPuXAHF43omrl7voXA311+59A6+FnpTdlzTeaSq5bDY0oT2LtnS/vI325Hnjq3bG2k/w5QNL9LIJDdvbsMuFqcA==
X-Received: by 2002:a25:d055:0:b0:dcc:1062:47c0 with SMTP id h82-20020a25d055000000b00dcc106247c0mr1727997ybg.56.1713528385871;
        Fri, 19 Apr 2024 05:06:25 -0700 (PDT)
X-Received: by 2002:a25:d055:0:b0:dcc:1062:47c0 with SMTP id
 h82-20020a25d055000000b00dcc106247c0mr1727979ybg.56.1713528385554; Fri, 19
 Apr 2024 05:06:25 -0700 (PDT)
MIME-Version: 1.0
References: <20240307135130.14919-1-npache@redhat.com> <CA+fCnZe+W+Umcc59=N5b2brN966qdUjb6vo=LjptJ=FdDPiCwg@mail.gmail.com>
In-Reply-To: <CA+fCnZe+W+Umcc59=N5b2brN966qdUjb6vo=LjptJ=FdDPiCwg@mail.gmail.com>
From: Nico Pache <npache@redhat.com>
Date: Fri, 19 Apr 2024 06:05:59 -0600
Message-ID: <CAA1CXcBzGGBqk5PXC9Q3gbwENgiZeQCqL7eVWvJnO9J=y982sg@mail.gmail.com>
Subject: Re: [BUG REPORT] Multiple KASAN kunit test failures
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: walter-zh.wu@mediatek.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UKpSSIcu;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Thu, Mar 7, 2024 at 2:46=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>
> Hi Nico,
>
> This might be related to
> https://twitter.com/andreyknvl/status/1632436931345670144.
Hi Andrey,

I dont think that's the issue. this is occurring with gcc13 and 14
(both which have that commit)
>
> Do you observe these failures on latest upstream (with the same
> .config and toolchain)?
Yes, sorry for the late reply, we had some CI updates/outage right
after sending this that were preventing me from investigating further.
>
> If so, please share the .config and the compiler version that you use.
Its occurring on Fedora with GCC 14.0.1
config: https://s3.amazonaws.com/arr-cki-prod-trusted-artifacts/trusted-art=
ifacts/1258913823/test_x86_64/6660914016/artifacts/run.done.01/job.01/recip=
es/15980336/tasks/5/logs/kernel_6.9.0-0.rc4.20240418git8cd26fd90c1a.40.eln1=
36.x86_64%2Bdebug_config.log

latest occurrence was today on v6.9-rc4
console log: https://s3.amazonaws.com/arr-cki-prod-trusted-artifacts/truste=
d-artifacts/1258913823/test_x86_64/6660914016/artifacts/run.done.02/results=
_0001/console.log
>
> If not, you can try bisecting to find out the guilty commit, and
> perhaps a fix will become apparent after that.
>
> Thank you!
>
> On Thu, Mar 7, 2024 at 2:51=E2=80=AFPM Nico Pache <npache@redhat.com> wro=
te:
> >
> > Hi,
> >
> > A number of KASAN KUnit tests have been failing on the upstream rhel/fe=
dora
> > kernels.
> >
> > cki-project data warehouse : https://datawarehouse.cki-project.org/issu=
e/1972
> >
> > The kmalloc_oob_in_memset* tests are failing and the
> > kmalloc_memmove_negative_size is panicing.
> >
> > Arches: X86_64, ARM64, S390x, ppc64le
> > First Appeared: ~6.3.rc5
> >
> > Failing Tests:
> >  - kmalloc_oob_in_memset
> >  - kmalloc_oob_memset_2
> >  - kmalloc_oob_memset_4
> >  - kmalloc_oob_memset_8
> >  - kmalloc_oob_memset_16
> >  - kmalloc_memmove_negative_size (PANIC)
> >
> > trace:
> >      # kmalloc_oob_in_memset: EXPECTATION FAILED at mm/kasan/kasan_test=
.c:565
> >      KASAN failure expected in "memset(ptr, 0, size + KASAN_GRANULE_SIZ=
E)", but none occurred
> >      not ok 17 kmalloc_oob_in_memset
> >      # kmalloc_oob_memset_2: EXPECTATION FAILED at mm/kasan/kasan_test.=
c:495
> >      KASAN failure expected in "memset(ptr + size - 1, 0, memset_size)"=
, but none occurred
> >      not ok 18 kmalloc_oob_memset_2
> >      # kmalloc_oob_memset_4: EXPECTATION FAILED at mm/kasan/kasan_test.=
c:513
> >      KASAN failure expected in "memset(ptr + size - 3, 0, memset_size)"=
, but none occurred
> >      not ok 19 kmalloc_oob_memset_4
> >      # kmalloc_oob_memset_8: EXPECTATION FAILED at mm/kasan/kasan_test.=
c:531
> >      KASAN failure expected in "memset(ptr + size - 7, 0, memset_size)"=
, but none occurred
> >      not ok 20 kmalloc_oob_memset_8
> >      # kmalloc_oob_memset_16: EXPECTATION FAILED at mm/kasan/kasan_test=
.c:549
> >      KASAN failure expected in "memset(ptr + size - 15, 0, memset_size)=
", but none occurred
> >      not ok 21 kmalloc_oob_memset_16
> >  BUG: unable to handle page fault for address: ffff888109480000
> >  #PF: supervisor write access in kernel mode
> >  #PF: error_code(0x0003) - permissions violation
> >  PGD 13dc01067 P4D 13dc01067 PUD 100276063 PMD 104440063 PTE 8000000109=
480021
> >  Oops: 0003 [#1] PREEMPT SMP KASAN PTI
> >  CPU: 0 PID: 216780 Comm: kunit_try_catch Tainted: G    B   W  OE  X N-=
------  ---  6.8.0-0.rc7.57.test.eln.x86_64+debug #1
> >  Hardware name: Red Hat KVM, BIOS 1.15.0-2.module+el8.6.0+14757+c25ee00=
5 04/01/2014
> >  RIP: 0010:memmove+0x28/0x1b0
> >  Code: 90 90 f3 0f 1e fa 48 89 f8 48 39 fe 7d 0f 49 89 f0 49 01 d0 49 3=
9 f8 0f 8f b5 00 00 00 48 83 fa 20 0f 82 01 01 00 00 48 89 d1 <f3> a4 c3 cc=
 cc cc cc 48 81 fa a8 02 00 00 72 05 40 38 fe 74 43 48
> >  RSP: 0018:ffffc9000160fd50 EFLAGS: 00010286
> >  RAX: ffff888109448500 RBX: ffff888109448500 RCX: fffffffffffc84fe
> >  RDX: fffffffffffffffe RSI: ffff888109480004 RDI: ffff888109480000
> >  RBP: 1ffff920002c1fab R08: 0000000000000000 R09: 0000000000000000
> >  R10: ffff888109448500 R11: ffffffff9a1d1bb4 R12: ffffc900019c7610
> >  R13: fffffffffffffffe R14: ffff888060919000 R15: ffffc9000160fe48
> >  FS:  0000000000000000(0000) GS:ffff888111e00000(0000) knlGS:0000000000=
000000
> >  CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> >  CR2: ffff888109480000 CR3: 000000013b120004 CR4: 0000000000770ef0
> >  DR0: 0000000000430c70 DR1: 0000000000000000 DR2: 0000000000000000
> >  DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000600
> >  PKRU: 55555554
> >  Call Trace:
> >   <TASK>
> >   ? __die+0x23/0x70
> >   ? page_fault_oops+0x136/0x250
> >   ? __pfx_page_fault_oops+0x10/0x10
> >   ? memmove+0x28/0x1b0
> >   ? exc_page_fault+0xf9/0x100
> >   ? asm_exc_page_fault+0x26/0x30
> >   ? kasan_save_track+0x14/0x30
> >   ? memmove+0x28/0x1b0
> >   kmalloc_memmove_negative_size+0xdf/0x200 [kasan_test]
> >   ? __pfx_kmalloc_memmove_negative_size+0x10/0x10 [kasan_test]
> >   ? kvm_clock_get_cycles+0x18/0x30
> >   ? ktime_get_ts64+0xce/0x280
> >   kunit_try_run_case+0x1b1/0x490 [kunit]
> >   ? do_raw_spin_trylock+0xb4/0x180
> >   ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
> >   ? trace_irq_enable.constprop.0+0x13d/0x180
> >   ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10 [kunit]
> >   ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
> >   kunit_generic_run_threadfn_adapter+0x4e/0xa0 [kunit]
> >   kthread+0x2f2/0x3c0
> >   ? trace_irq_enable.constprop.0+0x13d/0x180
> >   ? __pfx_kthread+0x10/0x10
> >   ret_from_fork+0x31/0x70
> >   ? __pfx_kthread+0x10/0x10
> >   ret_from_fork_asm+0x1b/0x30
> >   </TASK>
> >   ...
> > --
> > 2.44.0
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20240307135130.14919-1-npache%40redhat.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAA1CXcBzGGBqk5PXC9Q3gbwENgiZeQCqL7eVWvJnO9J%3Dy982sg%40mail.gmai=
l.com.
