Return-Path: <kasan-dev+bncBCXLBLOA7IGBBRUMSPXQKGQEHZ2NKCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 98EC210E6A8
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Dec 2019 09:07:34 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id f16sf5595010wmb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Dec 2019 00:07:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575274054; cv=pass;
        d=google.com; s=arc-20160816;
        b=cDKsZZthQ0P/ciZPMzq/MpIbVMZTx1GkoR9NCL5nviZy9fMWh9eCH4fNwQk5CRMPXI
         TkmTKEmDWjgVwvvVWvxrLa9hW3Zw/jfnhdL/x2B7ZVyQNTZ8gK36ueuapCYq//CW9Q9h
         e+Xuc4yyfUlstKQQpOgP/qBV2GNIzXfcQIycdawDiv8dTU9/sDpf//z0GbJwpKKfu8k7
         D3SWyNXPp4sgY6A1mEPR82FHKbdFVZl5WscURZs7sp5BWAqcg8heEmAOch5vNwunBkSe
         FwiwAuO583YT0p45ipKGcWO8EMfg6pw1g+0Gm85/iUgQkR2ZJ2PC+VQgHvTN9cSSG8ck
         bB8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=EnZMoKOhCAF07uJevRnZB6/8ayevq0nGXMtZK+gaaW4=;
        b=U5xKt7QXoIc/Fb9r/6FMwf8+VYABeqvi3M3gZQ81YVZxwrD5spH6qhNzbYguv1Fu2y
         fxKfyxKs71qavAQVj5hEz0zUca0KiBo7qHz40LAx4riQcLdfuuZAvmzP4Mbl8Q1U7P8O
         AHT4awK338/d9ZQQYLDWgQPP7iOnDuhUWnXDqiAjPg/7nFlDbyfAIxPslniHeZltbUAO
         bmpGC6zsW0YkJPXucry2SNBVjSqBd/R7uiOfZG9wbC575NtA3ej8txHc4bQvVcetRemm
         f1L3GagnaN8sVO/KJivuHlKesUctG6lI0RUBbEUGwhRLTkBo5/M95sPSny48evud+bPg
         1NdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="NA9HB3/P";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnZMoKOhCAF07uJevRnZB6/8ayevq0nGXMtZK+gaaW4=;
        b=rPCVYXglmarsB3xst0/qVA7g8AP8vURRNR9eYuNNSlIVm3RPx2AeiV8Qm9+PbqCbG4
         /NHgc+hMX/LBMaOt2JV157SKJcRuS+B1iFJqJlNK+ow7PcA0m9DyZNBvpTz3U1Yu313y
         8OuQAfTt22fhyE1k5FnzR5nHVmJfGvf5ZYmy0/jvkES1QHhWyWGsXG9DS3jAbZDue0j4
         gWmsQTLxh+NXht8SCqA9QAY9wjP5wOxVWd+8sMoO+F7ymZrJ0mROWiDproKFXLkiaVir
         3lTIRp53ngwrGffHIUNPutyC0Te4zySAQdSuEs443zeLg+yeLLxNYaXdTzHGVP5JPgw/
         HXqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnZMoKOhCAF07uJevRnZB6/8ayevq0nGXMtZK+gaaW4=;
        b=cg4iUoGzT8RHy2ARURbA/3HRWIqTfxlMyNtKkZifKKVU/1G5qKWC74MokfzvAbLFtW
         ByaD1VWK423d6emJofnyVHJ4Mt1m0CGotWoM59BLDW4my2V1FTUC480T43IAKPplUxl+
         T92XXnN3dHBAQ6e78ju4alpunnJNc3WXjjuifMt4EIro9ETPtFeAHrLvsVZBv6M+UvOP
         Wf31DzDVQ08ZFFI+QNkczVNNC37nF4l4G/TkXtQd2P/hDm+ojU7yXrg1CZkkXpLSwyLd
         H9ayj25QH8kmgarF+uZ/M0KAqFsj1pbLyAZ7+eujxOZTubOwaGI+DSGAnjL0JbnredSg
         ppoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUT929bQN367f5flTnyMPknyXZxJeQ+RPr1W9H+fNGW0xMuHPZT
	dYlfNbT1NIFQVqO2fwc7qQg=
X-Google-Smtp-Source: APXvYqyNROrLSyaqsvhcNoDEw1Od4kWTOpVn7EVKu+mRQvidg3Dv9EPxGzg++7kPlnFQwdN4g4Bsng==
X-Received: by 2002:a5d:4a8c:: with SMTP id o12mr51515765wrq.43.1575274054264;
        Mon, 02 Dec 2019 00:07:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:44:: with SMTP id 65ls1691757wma.4.canary-gmail; Mon, 02
 Dec 2019 00:07:33 -0800 (PST)
X-Received: by 2002:a1c:b1c3:: with SMTP id a186mr27307501wmf.10.1575274053723;
        Mon, 02 Dec 2019 00:07:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575274053; cv=none;
        d=google.com; s=arc-20160816;
        b=UsL5zFsKM8zGJ4I6WH5eN/tjBDG3n995FcRjX3qMHKK189L3HEe7MFFHtd7nPZIEJo
         fyCfRaamlTqeB1560DI9Hck+h6HMHfCajLZBE6ALK3SOkhof0rTdmla+32kxB7sHU+r1
         R8k7yWXRP7uA5wYJ5kmgRHoWjbiPT640ROD7z6kmr6AUycf7QfKuOKC2C68GEXJpcal6
         7g1d5EbVo3DADcL4Yeimm/J/PP+7rFv0ay0pzvn9D+kTu87czg4ARLIVV09MqQY4gFvW
         i0F1VJdQocbU7e/pwjUSFu94TjdzUl9fFf6lHT2JSrKuBzMyJc/M4hpFuB86EI2Y40S/
         i2wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Pfkmv+6zl1ejxY4eGUsKi0YsAcRI6StbPSFCVUfcymU=;
        b=TXlGXWeFcT/Fnx3MQkhPZr9X+f567NcQVL2A+JAyfdfJw0X2yYAG0czalzSWJmzKPw
         EH8IrZqDo/r4NGi54aicf6df53BKOQHOLAfYEWl4kJoh4sGNREGeSe2Rq59670qfb8oX
         NYdc4xgPXWI4AQ1K8OuUwwyNc517XLs4uVxOvddwx3VyL+g9q5Rslgm9MkGLvzYUiDNv
         Uq1Qn86bUOIJQ3NFtvQ3jG0iqaHWRWonDkJsLjtHF8h2dN7irmMPkh2lhDA4XKJZYEpj
         54HEI+hgb7en8ToQOEaVCo2kSyp5XFRVCp1W3kIaqbyE+qYBOlgELibuiyhQmfdwQQWA
         tthQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="NA9HB3/P";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id k189si719893wma.0.2019.12.02.00.07.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Dec 2019 00:07:33 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47RHlh4V2zz9txst;
	Mon,  2 Dec 2019 09:07:28 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id jENeedGZyhzE; Mon,  2 Dec 2019 09:07:28 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47RHlh3D7wz9txsq;
	Mon,  2 Dec 2019 09:07:28 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0FD2F8B79B;
	Mon,  2 Dec 2019 09:07:33 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id O4E_l5RfgFtW; Mon,  2 Dec 2019 09:07:32 +0100 (CET)
Received: from [172.25.230.103] (po15451.idsi0.si.c-s.fr [172.25.230.103])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C0DD68B770;
	Mon,  2 Dec 2019 09:07:32 +0100 (CET)
Subject: Re: [PATCH v11 0/4] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191031093909.9228-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <33b29093-5fbe-c648-a0b1-e3a8525c5631@c-s.fr>
Date: Mon, 2 Dec 2019 09:07:31 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191031093909.9228-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b="NA9HB3/P";       spf=pass
 (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 31/10/2019 =C3=A0 10:39, Daniel Axtens a =C3=A9crit=C2=A0:
> Currently, vmalloc space is backed by the early shadow page. This
> means that kasan is incompatible with VMAP_STACK.
>=20
> This series provides a mechanism to back vmalloc space with real,
> dynamically allocated memory. I have only wired up x86, because that's
> the only currently supported arch I can work with easily, but it's
> very easy to wire up other architectures, and it appears that there is
> some work-in-progress code to do this on arm64 and s390.

There is also work for providing VMAP_STACK on powerpc32. There is a=20
series waiting to be merged at=20
https://patchwork.ozlabs.org/project/linuxppc-dev/list/?series=3D145109

Christophe

>=20
> This has been discussed before in the context of VMAP_STACK:
>   - https://bugzilla.kernel.org/show_bug.cgi?id=3D202009
>   - https://lkml.org/lkml/2018/7/22/198
>   - https://lkml.org/lkml/2019/7/19/822
>=20
> In terms of implementation details:
>=20
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
>=20
> Instead, share backing space across multiple mappings. Allocate a
> backing page when a mapping in vmalloc space uses a particular page of
> the shadow region. This page can be shared by other vmalloc mappings
> later on.
>=20
> We hook in to the vmap infrastructure to lazily clean up unused shadow
> memory.
>=20
> Testing with test_vmalloc.sh on an x86 VM with 2 vCPUs shows that:
>=20
>   - Turning on KASAN, inline instrumentation, without vmalloc, introuduce=
s
>     a 4.1x-4.2x slowdown in vmalloc operations.
>=20
>   - Turning this on introduces the following slowdowns over KASAN:
>       * ~1.76x slower single-threaded (test_vmalloc.sh performance)
>       * ~2.18x slower when both cpus are performing operations
>         simultaneously (test_vmalloc.sh sequential_test_order=3D1)
>=20
> This is unfortunate but given that this is a debug feature only, not
> the end of the world. The benchmarks are also a stress-test for the
> vmalloc subsystem: they're not indicative of an overall 2x slowdown!
>=20
>=20
> v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.ne=
t/
> v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.ne=
t/
>   Address review comments:
>   - Patch 1: use kasan_unpoison_shadow's built-in handling of
>              ranges that do not align to a full shadow byte
>   - Patch 3: prepopulate pgds rather than faulting things in
> v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.ne=
t/
>   Address comments from Mark Rutland:
>   - kasan_populate_vmalloc is a better name
>   - handle concurrency correctly
>   - various nits and cleanups
>   - relax module alignment in KASAN_VMALLOC case
> v4: https://lore.kernel.org/linux-mm/20190815001636.12235-1-dja@axtens.ne=
t/
>   Changes to patch 1 only:
>   - Integrate Mark's rework, thanks Mark!
>   - handle the case where kasan_populate_shadow might fail
>   - poision shadow on free, allowing the alloc path to just
>       unpoision memory that it uses
> v5: https://lore.kernel.org/linux-mm/20190830003821.10737-1-dja@axtens.ne=
t/
>   Address comments from Christophe Leroy:
>   - Fix some issues with my descriptions in commit messages and docs
>   - Dynamically free unused shadow pages by hooking into the vmap book-ke=
eping
>   - Split out the test into a separate patch
>   - Optional patch to track the number of pages allocated
>   - minor checkpatch cleanups
> v6: https://lore.kernel.org/linux-mm/20190902112028.23773-1-dja@axtens.ne=
t/
>   Properly guard freeing pages in patch 1, drop debugging code.
> v7: https://lore.kernel.org/linux-mm/20190903145536.3390-1-dja@axtens.net=
/
>      Add a TLB flush on freeing, thanks Mark Rutland.
>      Explain more clearly how I think freeing is concurrency-safe.
> v8: https://lore.kernel.org/linux-mm/20191001065834.8880-1-dja@axtens.net=
/
>      rename kasan_vmalloc/shadow_pages to kasan/vmalloc_shadow_pages
> v9: https://lore.kernel.org/linux-mm/20191017012506.28503-1-dja@axtens.ne=
t/
>      (attempt to) address a number of review comments for patch 1.
> v10: https://lore.kernel.org/linux-mm/20191029042059.28541-1-dja@axtens.n=
et/
>       - rebase on linux-next, pulling in Vlad's new work on splitting the
>         vmalloc locks.
>       - after much discussion of barriers, document where I think they
>         are needed and why. Thanks Mark and Andrey.
>       - clean up some TLB flushing and checkpatch bits
> v11: Address review comments from Andrey and Vlad, drop patch 5, add benc=
hmarking
>       results.
>=20
> Daniel Axtens (4):
>    kasan: support backing vmalloc space with real shadow memory
>    kasan: add test for vmalloc
>    fork: support VMAP_STACK with KASAN_VMALLOC
>    x86/kasan: support KASAN_VMALLOC
>=20
>   Documentation/dev-tools/kasan.rst |  63 ++++++++
>   arch/Kconfig                      |   9 +-
>   arch/x86/Kconfig                  |   1 +
>   arch/x86/mm/kasan_init_64.c       |  61 ++++++++
>   include/linux/kasan.h             |  31 ++++
>   include/linux/moduleloader.h      |   2 +-
>   include/linux/vmalloc.h           |  12 ++
>   kernel/fork.c                     |   4 +
>   lib/Kconfig.kasan                 |  16 +++
>   lib/test_kasan.c                  |  26 ++++
>   mm/kasan/common.c                 | 231 ++++++++++++++++++++++++++++++
>   mm/kasan/generic_report.c         |   3 +
>   mm/kasan/kasan.h                  |   1 +
>   mm/vmalloc.c                      |  53 +++++--
>   14 files changed, 500 insertions(+), 13 deletions(-)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/33b29093-5fbe-c648-a0b1-e3a8525c5631%40c-s.fr.
