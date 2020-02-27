Return-Path: <kasan-dev+bncBCMIZB7QWENRBBFM37ZAKGQEUDGYHWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E0E01720B7
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 15:45:25 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id z5sf1858419pjq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 06:45:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582814724; cv=pass;
        d=google.com; s=arc-20160816;
        b=LpxP97KWdQ/dZr1uONnPHpIx+dBO61PozR7jcCWPETGPVcNXSVa41c8OJ9y9rpYeCZ
         y5l67+gAiM+4jE//tOeqI1Bnqqvftp8Q65nZNm65sHwUdCwK0Ge/K2WGI5o+fnbxjfyP
         NVd/JPq2KklUqkCwdsYI5reUs6To2EoQ5Tuy2QiGvsjoWVhmb5TuokLMNbW+jys94QnO
         fXPCkrFS2Ss18I87CRC6kY4pIuWJBWNLlDtzPPuehQWc/sVe1qO8vy71IpII71BNDVcF
         ZymAoc0U78a2XtQX7SGpWeGeTUOxWqGmm9tg7RTweRaw3HB7Xu0TvLYiPPeQnJFGTqJ7
         tQag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UFmdodvhchdLJud+L4m41hQD4arugy9qIr+MCO7nLgU=;
        b=UQl/2eOY/L4eNu5jVjEMeT8iQCyvP5wVuC6n09HkMxbSqywsmJWXQUowDaCLNv15WS
         n7frvg6LsLrR57K/M4V67JclVla9CVwHDnNMOhG2D2ZkPk591SU5cOi+3MAvsqu4u3h7
         0xgxqzWYfG/3doL//2iK0PgUJhlIA3AOYRny1PrQxQBpX6WCoDZfdU3TGeB0PQLMqbsM
         qSo1xhPh4GVeCQe39+JUv+GmHYSYolpNcAsYp5TNiNmTjF7KMfpqS26DDzIT8uKXF8fu
         N/VwCM3fbfTXMTzBgx/VT5d87JBSkHojZF64UByfcMAn7OWavq4HKk8V/uFg+BzHSOrQ
         NqZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VQBU8iu2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UFmdodvhchdLJud+L4m41hQD4arugy9qIr+MCO7nLgU=;
        b=RxpgxDsu6heIdqwu2sCiRx9tcaXb5Hj3Xee55HtVatEsAS4RXe24P8P/ZcEd3Xn+3R
         oTpD73Fm3V4VFwGKtIaexiaA/TBzJ0+8Z5BwPLw5HKpQ31Fk0PZXi7tnWjv4PysQA3iX
         wR0KSI8ui/DT+lQDpNCbG2AGKu4j7g0r6iQGWrOxi4Mw0HMl1Y15zZPs2nQVjwaBYbYB
         HdE0F38dALadPNXaCD4QIQZjAMYlMgEc/bV7mFW5QV1VcXq2eUqnHxeKDueS1ODifQJu
         HCFkqkKR149yavjAAlvnULr1qqxkivC/1KbECmWOKuqWCGHdya8WZdhxViMm5wPb7EGK
         66/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UFmdodvhchdLJud+L4m41hQD4arugy9qIr+MCO7nLgU=;
        b=OqPavzQDRaPoYZLmnM4X4kNhAQcFlvrMqSdYVnu6vKFfQ1515r+TJVQaqbLkpSDM1k
         NLlF35IA+0ruHJxmRfJhOjoYxwgVmoEFVYbrWeTdWdFAqzow2dQYQmnMs/hhiFckAmNq
         EuKuip1ibi0HbhuO707z0T3mis/jecYlg8ak6XoA1SEuCelUdmSnhu6UKbg98QD7PJem
         Z5D7J9lvXi0Y+KzGsviZ46XHYxjmXoG0clreylk3i7IQ50UD5eCtjg8VoFyqnAn2yz/Q
         CmunQaWpsP5YYYqFHhDaUsVnHSP8WnvdxOMIOpgEGKXVf9ZZsaUPiJOvHVCa6ToBDirm
         WpQQ==
X-Gm-Message-State: APjAAAUZNSb/9p2WrBrXgjnkJI2BqSseqRESgvTSuUmLHhztj6zu0DxX
	Z+BPGnvkneo+rq4Gt+b/ma0=
X-Google-Smtp-Source: APXvYqz7X9zrjuWxq5MyGsDO+DOhmqmhu/GQk9OKSzVyRo2SVrPfF6vVLO3QyxEArQuMMvbOS57aGw==
X-Received: by 2002:a62:5bc4:: with SMTP id p187mr3201196pfb.207.1582814724154;
        Thu, 27 Feb 2020 06:45:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:344d:: with SMTP id lj13ls1036716pjb.0.canary-gmail;
 Thu, 27 Feb 2020 06:45:23 -0800 (PST)
X-Received: by 2002:a17:90a:1f8c:: with SMTP id x12mr68951pja.27.1582814723408;
        Thu, 27 Feb 2020 06:45:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582814723; cv=none;
        d=google.com; s=arc-20160816;
        b=bUhqq0KNHWILXcdT7BWuMCiF40vfPBRIgRd+EGpvDJ4S68IDemmOcqffwuNs6ZXjrC
         +BcotyDJxg3ARQHVKq1rG2e2hgZ9JRAXyPi9QZipl6/AzNXlORLD89E6doe9Coibztap
         hf3ccH3FxvFwrDq9gahMqeRiFRR2Af2yjrHVQUIILkepAfRR293WNnrrQPNVPZoac0e0
         z2KdTcw+DL1E+O1vTaPvJcxI2Wa0buV1VNolvULUDc1r8j0RDkaER0kCnX0UHQkPoBBa
         inqBX1pxrbchxRMMZ5VPQQRxkoZErrN1AYHY4xA0HX2R6JzrIbPWVlCfHEfdIabr/ZNF
         YFjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uIt9DyZ9nPgtt+YVHDl4cWP+F6uXmWHM0NievYA3/mQ=;
        b=kasaSOoRU+y9n4f2vgfI62TrtDLTkR+mvy0dy6GLkeAvSY18Adq4kehJKkq09M2sNv
         P1sZoSmhjP84wmVgBZJJosKNE2UrbY22tVAz06FHDXPoP0Dqd1ErZqw5MxBd4UbT7ckw
         rOlciwCDyyAv/8TEMaU+F1EjGkaE1vPJ7vqxhcNCcSyyHytT4YxU98HIzJbAlQZllFl0
         2XBKDtCvMn/i9cklKUMyuBurfuc+D1fYcJpnJ/OZkHLKZkuDnmsJP54XDSh9XCGK8Tiq
         RQ4Jte+rd7gDI4jpV6jjiRAgVWJ2lmpAyBYrIDtp3oeELYHgb/khgxs3TM3Tabq9UEbj
         ZiTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VQBU8iu2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe42.google.com (mail-vs1-xe42.google.com. [2607:f8b0:4864:20::e42])
        by gmr-mx.google.com with ESMTPS id lt15si659469pjb.1.2020.02.27.06.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 06:45:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) client-ip=2607:f8b0:4864:20::e42;
Received: by mail-vs1-xe42.google.com with SMTP id c18so1979832vsq.7
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 06:45:23 -0800 (PST)
X-Received: by 2002:a67:f318:: with SMTP id p24mr2792811vsf.240.1582814722123;
 Thu, 27 Feb 2020 06:45:22 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com>
In-Reply-To: <20200227024301.217042-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2020 15:45:10 +0100
Message-ID: <CACT4Y+b0LHp15GNchK_TPxaqX8zscqgBw-Jm2Y3yq8Bn=dRbeQ@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VQBU8iu2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Integrate KASAN into KUnit testing framework.
>  - Fail tests when KASAN reports an error that is not expected
>  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
>  - KUnit struct added to current task to keep track of the current test
> from KASAN code
>  - Booleans representing if a KASAN report is expected and if a KASAN
>  report is found added to kunit struct
>  - This prints "line# has passed" or "line# has failed"
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

This does not build for me:

$ make
scripts/kconfig/conf  --syncconfig Kconfig
  CC      arch/x86/kernel/asm-offsets.s
  UPD     include/generated/asm-offsets.h
  CALL    scripts/checksyscalls.sh
  CALL    scripts/atomic/check-atomics.sh
  DESCEND  objtool
  CC      init/main.o
In file included from ./include/linux/uaccess.h:11,
                 from ./arch/x86/include/asm/fpu/xstate.h:5,
                 from ./arch/x86/include/asm/pgtable.h:26,
                 from ./include/linux/kasan.h:15,
                 from ./include/linux/slab.h:136,
                 from ./include/kunit/test.h:16,
                 from ./include/linux/sched.h:35,
                 from ./include/linux/ioprio.h:5,
                 from ./include/linux/fs.h:39,
                 from ./include/linux/proc_fs.h:9,
                 from init/main.c:18:
./arch/x86/include/asm/uaccess.h: In function =E2=80=98set_fs=E2=80=99:
./arch/x86/include/asm/uaccess.h:31:9: error: dereferencing pointer to
incomplete type =E2=80=98struct task_struct=E2=80=99
   31 |  current->thread.addr_limit =3D fs;
      |         ^~
make[1]: *** [scripts/Makefile.build:268: init/main.o] Error 1
make: *** [Makefile:1681: init] Error 2


On bfdc6d91a25f4545bcd1b12e3219af4838142ef1 config:
https://pastebin.com/raw/nwnL2N9w

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bb0LHp15GNchK_TPxaqX8zscqgBw-Jm2Y3yq8Bn%3DdRbeQ%40mail.gm=
ail.com.
