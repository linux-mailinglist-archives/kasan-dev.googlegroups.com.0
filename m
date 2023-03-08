Return-Path: <kasan-dev+bncBCRKNY4WZECBBWMJUCQAMGQEQX66ZIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04F906AFD91
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 04:45:31 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id c13-20020a0566022d0d00b0074cc4ed52d9sf8139736iow.18
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 19:45:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678247129; cv=pass;
        d=google.com; s=arc-20160816;
        b=dlAH/+Dkrt6aL5/XbWeSHqvgtOeMYiKYtHdIkAo7oInnk5KTfDx0snexGLyOQQe5yk
         YnMt+yKHfvOGC3LB4INuyNS247GHN2pXRnqTCMp/5C/Q/zoYatn8OrTVE0HT4aNigFnW
         QLaSZR64NoxLW625GHaXhFnSsAAWdqw3jNN5cUw1r0rL/mEfWwXIxCMxBFrfo3Ly9dfN
         e8bzVMaCeo8jTFRE1Yo8hO+II6dFIjZi36h7nTkXb9jJ2RlfGA4QOzCcODCOVkUmTEui
         YJNzvfBGUCb5yA+oYs0LgI2GvAc7vLjZVo3OEhKGKIIHSuOeCte8xL86kO7GZgOnAXx7
         L+Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:cc:mime-version:message-id
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=MHryCuzqlSkBqQcMlYvXNC4nmCYCO+0NpJtDvm28GO0=;
        b=o3yfER57ElfI0bzLPFv755DfKVnH2hS9deuBQyvEX3t8L31rl4fvRHbvsB4PyeSJsV
         fwRFNLWu5r4W8fQMLlmBg6v3lh+AfvW0loQlePrXbBVpOTUdZSXohbHhEA5eXhaIj5fE
         lpSqzZJJZbCAC53ST7jar0lVG3Ko8RMSk9EoKBP1tloESbZVVOBpVz5XUQSbITzC2KEd
         7lZsxL27RVt5xvrkD9I8Zt2I0KitpQTak3DfeK2BfRJ/xJERZB3Sr3fpqmVWE8V1/kKb
         NEs9PHriFt3a9fgD3xV5t5efLs0MggpABsABkb/aEUiLiHNHijLcKbdLABogATSLnhGW
         7Uaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=0u+x9Dso;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678247129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:cc:mime-version:message-id:in-reply-to
         :subject:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MHryCuzqlSkBqQcMlYvXNC4nmCYCO+0NpJtDvm28GO0=;
        b=dfREa8f0FSUgwfX+cjPatIBUbqoSDm61FqYmrX3FTPB43dfcz86whF/iy/zjio6u8D
         iC7Mxo6kbhlx7hB3r4TpluzaTuEkXGyVbc21FOMlj7u973CVMyesWtvLGVmQL4F1wtdQ
         x6thN1Szu8eyffg1M22G9UtnUYEuy/cqcYK1E/V3aYnoz8itBF1FaBI8BGMgHSC+At1a
         aEPoDkLyEcXoN/9MuAXEQ79sVnKiffuVr92PNftbB/+yzInbY0BD19Updq7g/93N6U3R
         TlEvbTVPQKc6NY+1P3GDc4kAoxrA4VirAD3W9+2bJLfp1Th+nJ6gcReVV7bvPEHTYQSu
         3xMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678247129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:cc
         :mime-version:message-id:in-reply-to:subject:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MHryCuzqlSkBqQcMlYvXNC4nmCYCO+0NpJtDvm28GO0=;
        b=67OJrxyO2WUf0vhB0TWkKy7zAlhEn4MJ1bZ8+Qti6vB/egT95un6ZA/Yk8qDIMvZrV
         nw3PeGaXMvAOahQ7j8CVGTUjKZHIuQMnDSodYG4qU22RwwwCaA92cFPwFL9NCgakONXO
         nQ6u466w0L5/GICMiE4E87AfAf7XF4RY1336RfSoqPs6c+dw3UezRvajayfcdhylrydC
         iFPtFgN9AhpJwBaTNb6T9HWGYzX5HvObucfmnEJw7765C0MyyLx1Hg69UM4mkMP+1PaD
         FK6y4Zf9GtthPrd4tpmqpRNTsyq/kgBZXoTA1ltoEgbBwU3vR9MegFSsAOgUzqT0Zyn2
         xxUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUOQ79fu+32LwORVXSK1fclODWrpf7jqj/X27Vp7kWQDmosmAyN
	LJJFEljnwLsDWENS+g39w/Q=
X-Google-Smtp-Source: AK7set+Attr0pNdco7tLCAM467m6fJqazhKbxxrSOwPOyXJpB/dyLMyB2Qe/Y2GlyWcIU79EjxObXw==
X-Received: by 2002:a5d:8d87:0:b0:744:f5bb:6e60 with SMTP id b7-20020a5d8d87000000b00744f5bb6e60mr8345250ioj.1.1678247129650;
        Tue, 07 Mar 2023 19:45:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2806:0:b0:316:e54a:82ff with SMTP id l6-20020a922806000000b00316e54a82ffls4306929ilf.10.-pod-prod-gmail;
 Tue, 07 Mar 2023 19:45:29 -0800 (PST)
X-Received: by 2002:a05:6e02:2164:b0:313:ac1c:24e2 with SMTP id s4-20020a056e02216400b00313ac1c24e2mr12705972ilv.9.1678247129049;
        Tue, 07 Mar 2023 19:45:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678247129; cv=none;
        d=google.com; s=arc-20160816;
        b=tJiIn5TrhHk7CLb7rcp4Qui/Jv/Lk+hazkvgrjf9rSH0MSjfFYt09F55f7d6MIy1GO
         Gcmf3hV/tyxrDOvAzs3aAGm+YU2SqGLZiq2fFzYSIbO3f3rFZxbdLqHpIRCCFyeQJlTj
         pRGieqV3jX8DkoMxQxH3FCUKMObmA0tGQgaErOINJnuPseiUH42HUCFK+WbLrY3dQvK4
         ud2sT/cuEmUEUxyoIQP5M5s8TvqsYAPWUFp/26SIrlkDt4NT/1AQf9NKi+aLIjC3f2cm
         s4rWGPhvbMjyHNhJUH42GA3S/Qh4BgScwfyF7VlUEeAJsXFPDFFL4vP8CGpBVudBFyFN
         1M6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:cc:content-transfer-encoding:mime-version:message-id
         :in-reply-to:subject:date:dkim-signature;
        bh=v4ZCOc3mfCj0AC3biqgCZENtlzkJ+33Pb7B/SIsDo+k=;
        b=xR5lbQwapTLkAQNsbNsquGnPOT6S6Ic+tHnh454gDlC3JrVcWsRXqlUnNKyd2qmGe7
         4AO6ktTKakVhN5USYtZkenhEmz4s3ZtXGKiBAryk4ctajzq26peFcu/S+KCoAreClGhK
         WngpHT+8GqRk0Ikr12bExwyOaFk+XCJfigEYdxrsZKIXLB7SOcihnuThNfqMPiPa93Vz
         yadlB40+p5QwExi2D3OZmt/vN2Sbwszz+88STFkPC1togHhb1QMWFhoRJkH3JkXCCu3I
         AjsktYY/HRqhPp3erRUx2YeJkh39jOYTs78urwo/62u3HTWgvj4VP3TmX2s0T+n3T0vP
         AOqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=0u+x9Dso;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 14-20020a056e0216ce00b0031580b246e4si768663ilx.2.2023.03.07.19.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Mar 2023 19:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id a2so16503382plm.4
        for <kasan-dev@googlegroups.com>; Tue, 07 Mar 2023 19:45:28 -0800 (PST)
X-Received: by 2002:a17:902:ea0c:b0:19a:727e:d4f3 with SMTP id s12-20020a170902ea0c00b0019a727ed4f3mr23665335plg.5.1678247128449;
        Tue, 07 Mar 2023 19:45:28 -0800 (PST)
Received: from localhost ([135.180.224.71])
        by smtp.gmail.com with ESMTPSA id ko16-20020a17090307d000b0019472226769sm9069473plb.251.2023.03.07.19.45.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 Mar 2023 19:45:27 -0800 (PST)
Date: Tue, 07 Mar 2023 19:45:27 -0800 (PST)
Subject: Re: [PATCH v4 0/6] RISC-V kasan rework
In-Reply-To: <167824615129.30763.10646446884793553712.b4-ty@rivosinc.com>
Message-ID: <mhng-0481a843-8d7f-4f2d-b110-f357324c7c73@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
CC: aou@eecs.berkeley.edu, andreyknvl@gmail.com, vincenzo.frascino@arm.com,
  linux-efi@vger.kernel.org, kasan-dev@googlegroups.com, Paul Walmsley <paul.walmsley@sifive.com>,
  glider@google.com, ryabinin.a.a@gmail.com, linux-riscv@lists.infradead.org, ardb@kernel.org,
  linux-kernel@vger.kernel.org, dvyukov@google.com, Conor Dooley <conor@kernel.org>
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexghiti@rivosinc.com
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=0u+x9Dso;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 07 Mar 2023 19:29:11 PST (-0800), Palmer Dabbelt wrote:
>
> On Fri, 3 Feb 2023 08:52:26 +0100, Alexandre Ghiti wrote:
>> As described in patch 2, our current kasan implementation is intricate,
>> so I tried to simplify the implementation and mimic what arm64/x86 are
>> doing.
>>
>> In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
>> instrumentation: all kasan configurations were tested on a large ubuntu
>> kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.
>>
>> [...]
>
> Applied, thanks!
>
> [1/6] riscv: Split early and final KASAN population functions
>       https://git.kernel.org/palmer/c/70a3bb1e1fd9
> [2/6] riscv: Rework kasan population functions
>       https://git.kernel.org/palmer/c/fec8e4f66e4d
> [3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
>       https://git.kernel.org/palmer/c/1cdf594686a3
> [4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
>       https://git.kernel.org/palmer/c/415e9a115124
> [5/6] riscv: Fix ptdump when KASAN is enabled
>       https://git.kernel.org/palmer/c/fe0c8624d20d
> [6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
>       https://git.kernel.org/palmer/c/4cdc06c5c741
>
> Best regards,

Sorry, this one didn't actually get tested -- I'd thought it was in the 
queue before I kicked off the run, but it wasn't.  It's testing now, 
I've dropped it from for-next for a bit as I don't remember if this is 
one of the patch sets that had a bulid/test failure.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-0481a843-8d7f-4f2d-b110-f357324c7c73%40palmer-ri-x1c9.
