Return-Path: <kasan-dev+bncBCMIZB7QWENRBAUE62BQMGQEOVNZKUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 065E93642BC
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 15:13:40 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id f2-20020a63c5020000b02901fc39812e44sf6158428pgd.6
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 06:13:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618838018; cv=pass;
        d=google.com; s=arc-20160816;
        b=qhATTFNPw5aR2Cnn9zD5MaYeFzW2DEUYNOw75K50JBMpf26We85GT4iOaJ/Af3zWtM
         BncbbEK4aU/abxQ2Skb5rAk8GdYObHjzY4PhA/zip5zDWi6U3RDuZzEZV4KOA6VBnlMP
         m49drdAulsjgTlO8CeVr3MtD19fJbz/wgl2GhKO5g8UgrvG9jIWfjGCoyFzevXHWLhPC
         pOaugaTquD+jLw6d3cJNesqbmb9H0eOPSh+xtqq6MNETNoyIGuizkrzjVch8hKguPVDs
         gU/FHzuEtv4hIU+fcZA2RROJERQfsIeO76gBtmLhzLDTJE7Wswr9cCKYE3O5g95yXMDc
         1VnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Kb3SSZyE8y+Sg1ME+P8FmrtUH/ta/8mNvhtpH7fVGeE=;
        b=x6Rqw4ALfCowAnCai5QmcN2aecw9nnqVMIQXY+jpeI4XonxD2/W/4BTqj9K5tQselp
         vGWf9pcDO4TpVnVsEF5e1p1evyrmYa6zjEaYlMPOzrnBRJQn6OjGYpjoe2ZGkcTCCO+2
         w5CEr2WiDyo+IJ9G6BjkxRDQfM0G7gddtJdCW4heilWFTshtIRTOSeOL1iThdPGjBRWR
         2OKZfnSgzgRI2oEZX9lutfrXSCqGELE7J38c0MOVnYi22Zk/tFuLSFj1zwhW1uX/qKIg
         QV9IO6zdzvJQNsgtG0Agw/duIDSCHmAABQADFa3+my84ycPPSq/sR+9WR0ruXdk9To/L
         BWWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g1QTmJcw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Kb3SSZyE8y+Sg1ME+P8FmrtUH/ta/8mNvhtpH7fVGeE=;
        b=mKF9dGQpvOr2jfpM5n2AxJxte1QalvGcA2My7cLu4L5ydXyiE28feXYGWnFEuGiWnU
         RxBDSQ21WTyPGnfIWqIGZkRiPa8dPFvjnxsq/UG+X265wCdTITcJk1bufaGANOnGAzIj
         S1Qy9MBDaVcMGEJLuDYZEwGYF8uHTYBOYdCPBg1tOKTOmLGv7CnezcP+C9AtP/3iXxhX
         5Z/RMOMyVqqpIb6NoN77ECjKKGt4fgYRfm5M7jTXaQ9YzyWJDJfxC4K0tqz6e3Qe4Qwz
         F0P45AwDONsFycefbxRTthEdu/u2e+7HsCFq3VvxHWtTC+naB67kYvPkEmg9fBqVgwEo
         PxVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kb3SSZyE8y+Sg1ME+P8FmrtUH/ta/8mNvhtpH7fVGeE=;
        b=opni19Il74HNBZ04Q2KydT7+PbzaP1pqKSMSTc5DvLKwlMcM3VuSZgJqB0XjgHyqfa
         pTgg47Aegx2C+bkgBtd2Esx7yVKsixVo2lwRr8GwGms9LKoyvMbpye4wBXxjqa0sseYl
         pA8o6W+HA+5O9kht6a7qFqZJIh6eZ7UtR9YvadwhgPDWMgZyMTVJAnQcWE9J7Pl8TiI1
         Jme8SYa6A6nYwxUTZIH92d4THlzm9p4X5EJ0GMBz/3ZnqO3BXkWTw7DXVCoG6ZaXNhTs
         p3c6/G8yY1As3SRNgxZ3ENdOfwSe7+ad1sprDDdVFCUeE7KhvbTJLqYG5dOZ4mrc3urK
         HrYQ==
X-Gm-Message-State: AOAM530hNRTOCqGsBm0NFoPgxYSUfGphMeCx4e7IE6SQI65OphdlHm6F
	7FOdu8YZUXUbiWT8y+/idHk=
X-Google-Smtp-Source: ABdhPJyxBPAUgRum/5BtVkpbWkQRvH9j78eG6vvCvGf5OZUtuJvZO9MGirk7/4MjVT5aMyT/55GDUA==
X-Received: by 2002:a17:902:8c92:b029:e6:60ad:6924 with SMTP id t18-20020a1709028c92b02900e660ad6924mr22878483plo.16.1618838018313;
        Mon, 19 Apr 2021 06:13:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7102:: with SMTP id h2ls9528091pjk.0.canary-gmail;
 Mon, 19 Apr 2021 06:13:37 -0700 (PDT)
X-Received: by 2002:a17:902:ed06:b029:ec:7b39:9739 with SMTP id b6-20020a170902ed06b02900ec7b399739mr16811531pld.5.1618838017513;
        Mon, 19 Apr 2021 06:13:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618838017; cv=none;
        d=google.com; s=arc-20160816;
        b=agsirczTczobFaNlqvkCkj07sKSXUorXlIhF5roKeKmI/EKlji6JTkLXki5gl0MPdx
         rP9HJoXRylAKcGFVutM26gc+eF6L/TZWYTBb8BVWE3WV5PFomzspltymdvfYUiXZ6l9s
         hOlpNyaHX3VdwD27v3X9LINQIdTZ4Z4lkUC2Vtt7zQf4Hi09NvZW9GMJxGuaPElozgpX
         1sC5E7IQh3AcW19lWDV8Sm+S0JCKRihn7QSFbZqyVR+UeRBTFG3aMYZ6oJ3V0Vwcg04A
         7PTsZt3cXT8IHWrUzA4EP/aO98lF8LJmhtJkRxECW6tns8WH4Kq9xugQ7svjXXCSrRnp
         nK/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VLug9ePvkS8LLKjzVRHQ6N7lmqOnd17ZtdJpJfB7IQs=;
        b=o+R/el4OEb0F2tYG1xYm1ESq4DjrNj7wrFC56iqcYptYWyC/9BjOUVEII4fwganguF
         3VT92D2oR8kL+zxawwlvJqAbvksPIEy1bz5pY/Z+TGbVX150mIdQEMLLnYhqlneR5cwc
         5lmR8KGv/K+e4JvLWBenadGt4JEgk8hGQniYFtXB7UJbYxKqBsk0JPwcdWf73J6uP3v8
         XiiGchah08vVjszPtu57S5BA7/5uhe0rg/eqD+v15LbLo6ulMW9ABGrF80fQ7OPXzpgS
         X8b1/AXt8TkGRgSrjmk6gEdrsnvCUGR6NMH4KYu30LXjsaE1vBXLqt7Wx8TjBtp7VP4C
         rd6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g1QTmJcw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id s20si64235pfw.6.2021.04.19.06.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 06:13:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id j7so25964316qtx.5
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 06:13:37 -0700 (PDT)
X-Received: by 2002:ac8:110d:: with SMTP id c13mr11390301qtj.337.1618838016392;
 Mon, 19 Apr 2021 06:13:36 -0700 (PDT)
MIME-Version: 1.0
References: <OMC24C9bwe6Oe9sgHOQT8eXBEYkKb5VLpf_y3_9qixVF40nNHkqXZBIL0LMmFqg4PZ2-Amjc0MqjAOnYgN1t4zTMYDbXeIBIZyg77T7ZADE=@protonmail.com>
In-Reply-To: <OMC24C9bwe6Oe9sgHOQT8eXBEYkKb5VLpf_y3_9qixVF40nNHkqXZBIL0LMmFqg4PZ2-Amjc0MqjAOnYgN1t4zTMYDbXeIBIZyg77T7ZADE=@protonmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Apr 2021 15:13:24 +0200
Message-ID: <CACT4Y+YjtuiUvhqCB=KDf0Jd4ux0Q82tEoqiXdvaASxH-UYTEg@mail.gmail.com>
Subject: Re: KCOV on older GCC
To: Mike <nerdturtle2@protonmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g1QTmJcw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832
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

On Mon, Apr 19, 2021 at 2:52 PM Mike <nerdturtle2@protonmail.com> wrote:
>
> Hi Dmitry,
>
> I was on your Linux Foundations talk a while back and really got me inter=
ested into fuzzing. (Awesome talk by the way :) )
>
> I've been trying to get Syzkaller with KCOV+KASAN working on my spare and=
roid phone with varying results. I can get Syzkaller running but have been =
having trouble getting KCOV working.
>
> It is a GCC based kernel: https://opensource.samsung.com/uploadSearch?sea=
rchValue=3DSM-A105F  Version: Linux kernel version: Linux localhost 4.4.177=
 #1 SMP PREEMPT (Version A105FNXXS4BTG1 from Samsung open source)
>
> So it doesn't support KCOV out the box as it's not Clang, but I saw in yo=
ur post on the mailing list (https://groups.google.com/g/syzkaller/c/fnYaR_=
Mz0MM) that we can support is with the SANCOV plugin from GCC 4.5, I am usi=
ng the latest NDK that supports GCC Android NDK, Revision r17c (June 2018) =
which is running on 4.9.
>
> When I search the Kernel source for GCC_PLUGINS or HAVE_GCC_PLUGINS there=
 is no mention in the source/Makefiles and there is no $(src)/scripts/gcc-p=
lugins folders created. But as the GCC compiler supports it how do I go abo=
ut adding the sancov plugin to the Kernel source?
>
> Will looking at a newer Samsung kernel that do support GCC plugins and tr=
ying to make the changes to the Make files to add whats missing work? As it=
's all down to the compiler and just the source needs to be modified right?=
 (I've had a look at the newer phones and they do mention HAVE_GCC_PLUGINS =
and GCC_PLUGINS)

+kasan-dev

Hi Mike,

It's probably not yet in v4.4.
When I checkout v4.9 I see these configs, but I don't see any of them
when I checkout v4.4.

CONFIG_HAVE_GCC_PLUGINS=3Dy
CONFIG_GCC_PLUGINS=3Dy
# CONFIG_GCC_PLUGIN_CYC_COMPLEXITY is not set
CONFIG_GCC_PLUGIN_SANCOV=3Dy
# CONFIG_GCC_PLUGIN_LATENT_ENTROPY is not set
CONFIG_ARCH_HAS_KCOV=3Dy
CONFIG_KCOV=3Dy
CONFIG_KCOV_INSTRUMENT_ALL=3Dy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYjtuiUvhqCB%3DKDf0Jd4ux0Q82tEoqiXdvaASxH-UYTEg%40mail.gm=
ail.com.
