Return-Path: <kasan-dev+bncBDW2JDUY5AORBGUYSKUAMGQEOBBMP2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id EEA697A23F6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 18:53:47 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6c0f174540csf3285227a34.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 09:53:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694796826; cv=pass;
        d=google.com; s=arc-20160816;
        b=PZ6fToQdfoAL1WKiWLEHQM9Qf/s/XGdU26wJova0LVc+cNpJ2pZRFJ6qNMjbrWUR3J
         1j3KRI+wPviqAIrhDLUq3C0py53VFOXqPjsv8bDIr5b1EXYcqGN2HifD/lQklEzQ+a0a
         ywn8v5v0tu7GyfVWoHn5HLsa+2lkZz2WUySZl+WKUgJLLTL235fXOg0nHk0dcPFvP58S
         1AiWdPCpIA+vjkh94SwykaA89Kumfpfa4v2uV41fc3rs9RJCgx8o+vRH8wKSRAVL/g/n
         kVFoCHJnqwHXIKXfMc8/BB1FDB5SopxIRpV1sX7klyHss+Hn5boIJWGnsyMy7/24LZAk
         8HAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ygxYNWS0Wkj4dKD8sx5aafzsiKIO/4YECVrigSa7MqQ=;
        fh=XnrzN0r/2aU4P5jFxOISiaBHfdFaktsvsLh8FBfzjKE=;
        b=O9oFAYRmgpe+i5FXhVJ/RTv/j9QMnozSB1hPi4qnUYRQxo52dVvsgoPn9YUup9pisa
         7A7AK1TPalcaGH0xi49+3OrvR2PAUhQTIUX6j5iz0kQzfxg+U2U7QMJIOZr4H8e1Ipkv
         I5WnjjM8x8IzT0oiBVPStds2+cTnVq/uqLaVGkRVKJjgQE4ugtFJMVoCjF/agNbWGr+J
         SqH5Ytn5Z74F+ie7zs0or5oDTVCekoUy6SJw5Zfsy6sUWeULLNWBpfrDTp1i0rz6Da/G
         x3lg5zwCQS3Fzkjr+7lLw8RuQa5cXV7jFluoaGFlOj47W8lXcK5pOr1dylJvQjupUJg5
         b4pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B7Psz2UY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694796826; x=1695401626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ygxYNWS0Wkj4dKD8sx5aafzsiKIO/4YECVrigSa7MqQ=;
        b=Qoj4felf22MDm8Le/p4C2ZVNWLshTlCDfOUUF7j27JX5x/WfTKbsYn+djE0fJDXh1Q
         pElNVHgDQOrzlO5sR5ehW7AapImgV5oi2YnY3mpw8LPFbGuhdk1eJRUauM1XMeMk4BUs
         XOPa7AQB1KFmjQUgiNxgq2TpqLHTBiz9M8cebtZASYyd3LVG1J57YF8IFwctD9lkvcyO
         VmeZExWopjKR9McZjkSO1y6+xK0Pn3g31QA1rvDVbXQ0OzIjVxpjkRYm6naD5IuTEttY
         D3d/qlpWvzWK3vMPDWJ/1mTlu0cuB97QNliFNqZIh8XOBahPtc/UdIpI3Haw6ufvKluR
         X1GA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694796826; x=1695401626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ygxYNWS0Wkj4dKD8sx5aafzsiKIO/4YECVrigSa7MqQ=;
        b=a5quZ2SbRkV+S5eK+nWBPFO9YrVh4aKmrImAigDGGNTooJb2lQ1X+dmJLAex7P0RRh
         TKBKjGvGNiZ1s6oq/MQVuJ3SIe/WsalpZP702LFJWgQSGjQ8CQLawqYZHjvUOL7Bp7Lf
         RTPhFEl/dCHFhB25eLJtdXfz9P0y6Kfruj539JWBT6KQaFBJYUrRxBosVqcAtym0QP+S
         +y3P6bieFXSaL35d6NcoDGlCb7rfaegn+HSgbRzsQKbR0xkU8sXha3cmFUcMnf+sH2Ai
         rlC9NG3hgv62JkZO4nnzFTCFmK1sW/LpR5822OmS1am8ZgGPmv2rIQ6uBaiy22tFd9BU
         vsDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694796826; x=1695401626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ygxYNWS0Wkj4dKD8sx5aafzsiKIO/4YECVrigSa7MqQ=;
        b=lgzJhHubJ7YNLr4mUATzLSfqDT9u3gX/dzMTWT439KwWKlaV1ebGD8PEAQQXaNAKmx
         5GAAABUQkuv9BqH3HGUf+bKU19OzgE59gmXutJdBk13zAr1pAgdq+0Ggv3rOr2ibqQpm
         1JpTRO8RwE7r5+cN6QIdfUndAFjZs2Vu2fyWjaSBaJH9vY+SwyTm2vufxGy9W2s3J1QV
         EwkLn/YG7n+CSkymQVm/3qtko9d8z5jkfl+jrq+jk7vQxjgOyTFXjtiEc4/n7Ex5WjCe
         yF4eFjPW1e4faPHap1Lpst8i83kYswO1MdF4jPspRcbbZjrSFfungryPy3r5ALeYDhNk
         L9Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw/lg6X+9fSv+ibvzm7vWqQnaSoe3OLxkCzcOeiBOgl5/VmD9EH
	3npo2i8t4hpmMoOyNTZbU5Y=
X-Google-Smtp-Source: AGHT+IE2AISOZ4EPYPDbhREFMAeCAb7yNX83gosednYoghUaE70gmVnv3tOX8k0v3t9ixMW89rJbZg==
X-Received: by 2002:a9d:4b18:0:b0:6b9:37e2:76fc with SMTP id q24-20020a9d4b18000000b006b937e276fcmr2017975otf.30.1694796826610;
        Fri, 15 Sep 2023 09:53:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1549:b0:d80:904d:c223 with SMTP id
 r9-20020a056902154900b00d80904dc223ls499338ybu.0.-pod-prod-01-us; Fri, 15 Sep
 2023 09:53:45 -0700 (PDT)
X-Received: by 2002:a25:bf8b:0:b0:d81:65a9:ac6d with SMTP id l11-20020a25bf8b000000b00d8165a9ac6dmr2141980ybk.37.1694796825865;
        Fri, 15 Sep 2023 09:53:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694796825; cv=none;
        d=google.com; s=arc-20160816;
        b=XY6VQta0PmjFe4x55rfYHBZUy0tUtH0iR+A5ejIx79qQ2bDdj1URvJ/1i4TsrwQByP
         p/v4UsXPt/P8UTKO9GMDFdO2kO+T2lzL4iOuDhCLQq18r52zNclXgBH6YiEXCbB+eYH3
         F5ZD0dUCkc/oODXtUEtqzbrVLbTRQjVO4rYJ64sGAfzGjBFaKNFV0S+5DCWB+Yiac+CY
         ZBs6zsoojgy5MiQIDlnYIJU48Z6EKB+flgj8KaZaTXRx/+afu3mE8WqnSOPG23PjLKr3
         ePv33XB8lhsinaqhEhiFN1Yfh2j1U8rv0IzOn2x3j+NIa0FporKaysH3LrnihLtCrraS
         /w1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OpolqE+SEAVwVFTY41H2JAWAfBtJPW7sGVhV9bEg07M=;
        fh=XnrzN0r/2aU4P5jFxOISiaBHfdFaktsvsLh8FBfzjKE=;
        b=IsI7c06KDpv/HbjO9JqTJVC2niFjJFiCxLL3ptYUx6bvDqYMIOket1rIFC3G8ECh6Y
         ObFBIbumMR15u7aezUJUWsze8gAlM6LuvNQxbC+w6C5zNJV3t3EvakolKTCnZs1NfWbg
         mJEd3KsjsJedGG7BjGQ5/7k8b9gJyuTVDGgZk3/8KqElr4gnMCTRr0ljJLrI0HKlrl6B
         SaJeRWjApg1M9++MVjk1sMRpg1Gd80kgk0jRnqH2FmqjTToe2WWyVyvMMBl2BoX8BUbn
         a4L0fXk4o/ED7vaR9myhdxdIsK6TZ06ToKJgeabjYFEimoukzkVKqga3XPZKI4qkjtfG
         aHeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B7Psz2UY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id l134-20020a25258c000000b00d780ceaf524si534703ybl.2.2023.09.15.09.53.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 09:53:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1c3bd829b86so20170705ad.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 09:53:45 -0700 (PDT)
X-Received: by 2002:a17:903:1109:b0:1c3:bbad:9b7c with SMTP id
 n9-20020a170903110900b001c3bbad9b7cmr2546503plh.31.1694796825027; Fri, 15 Sep
 2023 09:53:45 -0700 (PDT)
MIME-Version: 1.0
References: <20230915024559.32806-1-haibo.li@mediatek.com> <20230915094004.113104-1-haibo.li@mediatek.com>
In-Reply-To: <20230915094004.113104-1-haibo.li@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Sep 2023 18:53:34 +0200
Message-ID: <CA+fCnZd0FkKNf1ZQxbXWvNM8NAt=ML+yXu5n4VgLOmhFf9TPfQ@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Haibo Li <haibo.li@mediatek.com>
Cc: akpm@linux-foundation.org, angelogioacchino.delregno@collabora.com, 
	dvyukov@google.com, glider@google.com, jannh@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mediatek@lists.infradead.org, 
	linux-mm@kvack.org, mark.rutland@arm.com, matthias.bgg@gmail.com, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B7Psz2UY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Sep 15, 2023 at 11:40=E2=80=AFAM 'Haibo Li' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> I checked inline mode just now.kasan_non_canonical_hook can print
> something like below:
>
> Unable to handle kernel paging request at virtual address ffffffb80aaaaaa=
a
> KASAN: maybe wild-memory-access in range [0xffffff80aaaaaaa0-0xffffff80aa=
aaaaaf]
>
> When addr < KASAN_SHADOW_OFFSET meets,the original addr_has_metadata shou=
ld return false
> and trigger kasan_report in kasan_check_range.

It should, but I don't think it always does. But if it works for you,
let's leave it at that. I'll double check why it failed for me later.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd0FkKNf1ZQxbXWvNM8NAt%3DML%2ByXu5n4VgLOmhFf9TPfQ%40mail.=
gmail.com.
