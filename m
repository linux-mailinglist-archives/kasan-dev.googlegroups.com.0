Return-Path: <kasan-dev+bncBDS5JPEL3IIRBCP63OTQMGQE2XD5YXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E2567921CF
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 12:12:26 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-500be41e54dsf2478291e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Sep 2023 03:12:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693908746; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6G4FqDOFX82/WHlq2frs7+tma+UhD7SL37m3iJl33XzTw8SBaBHLZnvyzkdPC8bPn
         RNfefIQOOb/eteFVaKA6llhR3AvRu9FRPi/B/wcF1Mr+xN3cean9+d0npisKtHsuAyRU
         XPmGIXov4cGlkgCOXlmTbNC5kYfubTpjq3Bs8+k2qDw0krWcmAQMmMt70qCsDRoCH4Vy
         98GNZSV0GxxBTowWkCpGBlEGTyf9jcT2jS/kd3F134LISClNk9gdb1AgNW165tzujb3A
         p5wGHsiZ6DWlT7B8cnVNWZzXzcciqhkJatTs/vfKiaHvGIFPOhSd46uBQdzwDlgQGhxQ
         1QLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Q2gdNjk6zDC7XxIlvdajp95DXBwr55q2DgwPFwQzfVE=;
        fh=UQ8X+l1t3cC/eiw3s7ow9b/DxrPjcdxxNxfJYvJ7kLs=;
        b=EsrTQq9d9Nm1y3O5Sz7lk9jbqSEZ06nkhOnuiiiTjtXHn7N6qV3XemiidqnYI+JLrv
         kaLdTEWW9/4f3u7kbHGAV7uTILo3xq3KZaT6Zdbf8RQc11MpvFld+gRtcRDT8zIbOOhe
         nYfDAsjlwfEUg7yUO05NpWHIFUvhOndtV5eDzw/6pEnPjBBXSej29pggpJHwxl7ae3yU
         Oan5csUesx+vcC+KyGqc+L23+Lj2EHgSpLZaB2Hp0ip826DIdZcE8fCYK+uxQcTZlcqe
         3c4nVVADom9iHA7cwRNjc+kqBvImDxipcX+o6tvaNQ/gOIuyugfC7WqWh4/wYrzfahKH
         vevA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=jyF4omO4;
       spf=pass (google.com: domain of lukas.bulwahn@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=lukas.bulwahn@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693908746; x=1694513546; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q2gdNjk6zDC7XxIlvdajp95DXBwr55q2DgwPFwQzfVE=;
        b=mxkKCy87CGyB9aqFYp9NM7MHHBpQRmK2ykISTpvNKwr4VYVZri5IfNt0UTfyDR6H+3
         5+ktB0yi23leh78/cY4qnP39Q0ne3qrvSkH9/gdn0Kab1eVF+Eoc0Rb7p7Rz/ALe89Vv
         gZgd131CBTqgtbj9cFNX/ZT7NXTpRp0PwHoJjcQsfdRMCo0qaILMvnBbf5+HopB5sAd4
         P9AAdIHw8binVdEOwSySjQaU0jPrRLZzLWaSDmcIfdUuttLrWKWIODXx1dfg6nAzBLVx
         Wl4O+bqHxbfJiQs3E8EGE0yNG5KHSUoeCjYPwk9kPJsc3h0zKwNHdZ6N8H6FQUYsvU/A
         GRcw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693908746; x=1694513546; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Q2gdNjk6zDC7XxIlvdajp95DXBwr55q2DgwPFwQzfVE=;
        b=Cb6E6UmW5fvgZu/9zivJfFsJA/x37bdPMqoX1Z/NBJr4XMVe+0ullDmHmbyPZw1Omc
         xkjYRdNOFt1bv+YJ/q50OgMIQXdlClGu7GNKyMnMT7T6zaDiBAHxjMGZRQjLAaRxMpKk
         0DHCrDu/+eZ4c3EAf610xQylcnaneto8cxoSUBTkiQqjsieHgpukgDzGq+34t0BKgq1+
         eDSdM6b1Zo/sZDurBBP+PBbMsIyiyaAP1CGUUTuHg18EKIq2YwkoOWXxwaJeN+zVF07B
         HLaTNpXwrjZX8UHJzXhR/T248G9nKATS56i/aV7rajf6ROavEqg8NHecYgeAJh2bFFFD
         CHOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693908746; x=1694513546;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q2gdNjk6zDC7XxIlvdajp95DXBwr55q2DgwPFwQzfVE=;
        b=jBKd+umFE4gTZLxl+FEqpQT00Gzw6/JTsh7oR/2m0IOTKuI5p3gnDJABbFKPdGzwU7
         YzFSwjTAzm6BtYO8KYXDYnhJVFRpkID8fJ6mRGOIQFgtVkgep2L8CVFw5bLDj5d19kOu
         dOz84ct/AcWF7EJyeF6awWvaH1hripvFu2ziaP+0i01sVxHA3pLJkDjElGJa6LsrK7mp
         JfBZ3w4bZqRX2a7OpoxsLY7o6d8Ow4bgQdtAnzzI3ygTCVfnAGI7VE2w+ct+Ktyi72Rq
         YwsmBXMzgumi4rNwL1/1InRGxyD8BHC0EpbS0cgg3fgIAi7kFrFRjrUz/H353fUpnCSL
         X6AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzXuKL5svtYlHejNH/Mm/0cfSIU9ucLrXHr/jL5reptRuPBb/gt
	4uPd/YQRUGqjcktcI/icJOg=
X-Google-Smtp-Source: AGHT+IHVCmirCQ2TxWD88FS2rRZ3atKkEQU5hkZtH1+GyoMwy5oSQ2Qe4BskB/uVw53J0xUNNvqLpw==
X-Received: by 2002:a19:711c:0:b0:500:7685:83d with SMTP id m28-20020a19711c000000b005007685083dmr7405847lfc.48.1693908745332;
        Tue, 05 Sep 2023 03:12:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6758:0:b0:4f9:5599:26a with SMTP id e24-20020a196758000000b004f95599026als1786375lfj.2.-pod-prod-08-eu;
 Tue, 05 Sep 2023 03:12:23 -0700 (PDT)
X-Received: by 2002:a05:6512:2005:b0:500:b8bc:bd9a with SMTP id a5-20020a056512200500b00500b8bcbd9amr7681631lfb.49.1693908743323;
        Tue, 05 Sep 2023 03:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693908743; cv=none;
        d=google.com; s=arc-20160816;
        b=A4v//sGbMYNJG/23p3+Ker72G43BuNKDZfqPwAdscngk7YDWoRWmFoNVQuab1M8ySg
         3KwBHJT1rxpdZ2FJX7MbwplbLyLqjxpuQ66GoMwsvvaz/VSJxVbudzfsVVvkAQuIFElG
         2DDirwePvTirULWtgNGIMha0LJreBnzOQ7z1YZJjRiGLNHRNyAz0g1OQXmg3dmCccjJT
         5ST+LHswh9pedeCecVLnFwsX4KGb4aCdbL7z5tFpYez7nyp+Td8BBatbJtUBvlpQKr5U
         xKcf+92r3bVEFmGRzGvPyjZ6ab+P8sR5cX+UkZ9r4dxTYlTzcKHzJOuL948KmI+jUBFt
         pW6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=e86Wy3ATT/OU246cW5x4ED89M09p8uuT794yspAsqs0=;
        fh=UQ8X+l1t3cC/eiw3s7ow9b/DxrPjcdxxNxfJYvJ7kLs=;
        b=onKli+1DUWfAjnbcZk5H9rz/q6UpN9mDCmI4sCULjLT9UESH4IWnRx3xW6GlMiudvH
         kvdYC1VSKrMIegCDySwE2UHx4QLuy3HZYsVLg2g0WmQQYd7l5pYJ2b2iS3UZ+CQSiNuZ
         fsoeWphYB4P46J7eRDNrTV7301T4WcCRvKYUXxb9GS5hEwEOLzDnLqu0/Zkzc5GTnmPt
         KXoCedPU9rYCNCqnvcKVrV4pDrcbFs4p7odDtLnsZ7AbDja6GOD/sOaFTNtJkI4ClnPh
         fz56s9ChM4a8J+wLNzCWW+VsQdgXbiJjI7d6F5dtsjlwxrm7sjgNpt/e/qu8Uo9jyeiO
         DAlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=jyF4omO4;
       spf=pass (google.com: domain of lukas.bulwahn@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=lukas.bulwahn@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id o2-20020a05651205c200b004ffa201cad8si816259lfo.9.2023.09.05.03.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Sep 2023 03:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lukas.bulwahn@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-99c3c8adb27so350482066b.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Sep 2023 03:12:23 -0700 (PDT)
X-Received: by 2002:a17:906:3185:b0:9a1:c00e:60c5 with SMTP id
 5-20020a170906318500b009a1c00e60c5mr9033774ejy.48.1693908742368; Tue, 05 Sep
 2023 03:12:22 -0700 (PDT)
MIME-Version: 1.0
From: Lukas Bulwahn <lukas.bulwahn@gmail.com>
Date: Tue, 5 Sep 2023 12:12:11 +0200
Message-ID: <CAKXUXMzR4830pmUfWnwVjGk94inpQ0iz_uXiOnrE2kyV7SUPpg@mail.gmail.com>
Subject: Include bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute
 checks") into linux-4.14.y
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Sasha Levin <sashal@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, llvm@lists.linux.dev, 
	linux- stable <stable@vger.kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	eb-gft-team@globallogic.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lukas.bulwahn@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=jyF4omO4;       spf=pass
 (google.com: domain of lukas.bulwahn@gmail.com designates 2a00:1450:4864:20::634
 as permitted sender) smtp.mailfrom=lukas.bulwahn@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Dear Andrey, dear Nick, dear Greg, dear Sasha,


Compiling the kernel with UBSAN enabled and with gcc-8 and later fails when:

  commit 1e1b6d63d634 ("lib/string.c: implement stpcpy") is applied, and
  commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") is
  not applied.

To reproduce, run:

  tuxmake -r docker -a arm64 -t gcc-13 -k allnoconfig --kconfig-add
CONFIG_UBSAN=y

It then fails with:

  aarch64-linux-gnu-ld: lib/string.o: in function `stpcpy':
  string.c:(.text+0x694): undefined reference to
`__ubsan_handle_nonnull_return_v1'
  string.c:(.text+0x694): relocation truncated to fit:
R_AARCH64_CALL26 against undefined symbol
`__ubsan_handle_nonnull_return_v1'

Below you find a complete list of architectures, compiler versions and kernel
versions that I have tested with.

As commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") is
included in v4.16, and commit 1e1b6d63d634 ("lib/string.c: implement stpcpy") is
included in v5.9, this is not an issue that can happen on any mainline release
or the stable releases v4.19.y and later.

In the v4.14.y branch, however, commit 1e1b6d63d634 ("lib/string.c: implement
stpcpy") was included with v4.14.200 as commit b6d38137c19f and commit
bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") from
mainline was not included yet. Hence, this reported failure with UBSAN can be
observed on v4.14.y with recent gcc versions.

Greg, once checked and confirmed by Andrey or Nick, could you please include
commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute checks") into
the linux-4.14.y branch?

The commit applies directly, without any change, on v4.14.200 to v4.14.325.

With that, future versions of v4.14.y will have a working UBSAN with the recent
gcc compiler versions.

Note: For any users, intending to run UBSAN on versions 4.14.200 to v4.14.325,
e.g., for bisecting UBSAN-detected kernel bugs on the linux-4.14.y branch, they
would simply need to apply commit bac7a1fff792 on those release versions.


Appendix of my full testing record:

For arm64 and x86-64 architecture, I tested this whole matrix of combinations of
building v4.14.200, i.e., the first version that failed with the reported build
failure and v4.14.325, i.e., the latest v4.14 release version at the time of
writing.

On v4.14.200 and on v4.14.325:

  x86_64:
    gcc-7:     unsupported configuration (according to tuxmake)
    gcc-8:     affected and resolved by cherry-picking bac7a1fff792
    gcc-9:     affected and resolved by cherry-picking bac7a1fff792
    gcc-10:    affected and resolved by cherry-picking bac7a1fff792
    gcc-11:
      v4.14.200 fails with an unrelated build error on this compiler and arch
      v4.14.325 affected and resolved by cherry-picking bac7a1fff792
    gcc-12:
      v4.14.200 fails with an unrelated build error on this compiler and arch
      v4.14.325 affected and resolved by cherry-picking bac7a1fff792
    gcc-13:
      v4.14.200 fails with an unrelated build error on this compiler and arch
      v4.14.325 affected and resolved by cherry-picking bac7a1fff792
    clang-9:   unsupported configuration (according to tuxmake)
    clang-10:  not affected, builds with and without cherry-picking bac7a1fff792
    clang-17:  not affected, builds with and without cherry-picking bac7a1fff792

  arm64:
    gcc-7:     unsupported configuration (according to tuxmake)
    gcc-8:     affected and resolved by cherry-picking bac7a1fff792
    gcc-9:     affected and resolved by cherry-picking bac7a1fff792
    gcc-10:    affected and resolved by cherry-picking bac7a1fff792
    gcc-11:    affected and resolved by cherry-picking bac7a1fff792
    gcc-12:    affected and resolved by cherry-picking bac7a1fff792
    gcc-13:    affected and resolved by cherry-picking bac7a1fff792
    clang-9:   unsupported configuration (according to tuxmake)
    clang-10:  not affected, builds with and without cherry-picking bac7a1fff792
    clang-17:  not affected, builds with and without cherry-picking bac7a1fff792


Best regards,

Lukas

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKXUXMzR4830pmUfWnwVjGk94inpQ0iz_uXiOnrE2kyV7SUPpg%40mail.gmail.com.
