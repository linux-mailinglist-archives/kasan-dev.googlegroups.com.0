Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCUSRDCAMGQEZBKPQHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4376EB1079A
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 12:21:00 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e8db89e6a79sf924848276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 03:21:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753352459; cv=pass;
        d=google.com; s=arc-20240605;
        b=f1H4GUvp7hcXLCwcw7wFLdpnHByRXtaH730XXwo+I5YQvQvYN4Gr3Gl788mNN4yJgg
         hiurOy3BPWK2qpShxto1ggxhmFiT/S1ErPGE1NjsdbLukI2uzRaSZNG4BM2thyz++9sl
         3BVW/l4X40XegE3ax4tUNdjot8VjB9aDpvO9JBMc8c4nYB2c5dEqTwQr8uXCyvTGOMyR
         pUyQww/XyEpPHqw0PfHwk4QU+/M/7G64rVDIDr76V1Do5nC0IptI0aHSMA/0zsv/A0O1
         n1THC+rO3HIscBamjSgOCmVpFqPLTNcUG8M3yawcTkJutgtVLHyfEgrV9S8vsetiAex7
         5g+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5V/D2Qn9Xc4CYsE9C7FqEG9WLu9HNaOPxt769lHd2ks=;
        fh=/HHcPGbPs+/gkbATxAVbiV8CH92JOLRAN4DQWNVR5fA=;
        b=g1AAmGjLn6K0Q2ZUKk7NbmRGSM7H50bFyfYRhd2w4SU8+GGU+jEM6Y+XhOz4oFq//p
         UrgNx8VpaUzMMsFB3VmPdQ+Sf0rjzlHqwDZSwO0uTYJ/r4Gdlw/LXCVgSSjvhoaKCvq4
         36u3K3sigDdODpopxRc2uf6B6m/1DQjBZg8RTn++djd8ZvaOaaoYxTxe8FB+RKsDek5G
         1U1Ax6pWb68YOphul/xc2MZpKQvX8gtJOpVT5EE6Rh+yBVMd5o9Eul8HnvWWAF7KW0rD
         PDmWvOGIvb0nP71eazgzpnFV4bJAD4jYPxDegnir2J5xWao14BGtQOoiV/gcZP82eCs8
         7X1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VYy4MeJy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753352459; x=1753957259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5V/D2Qn9Xc4CYsE9C7FqEG9WLu9HNaOPxt769lHd2ks=;
        b=BIu9ySnGSy9I4jliTrKHBV58bo/E1k69Vof/XLw0aYuZakC7bHZlrl26fcEKB6m2NZ
         9XP8LYw6qSJIAeglrgcIf/h/JpNFmu5bB6IqhaMDSRswfdt74w1DsoUaqS/IYuxvgff9
         GSdJ2ZvejGEbWW3ec/QAdr7TVI8wpf2ROqe3xXRCCXqsdseLs0OWwTmrdsFAnp2OXWRW
         Rmj+RL+z466jqpB/NM4Oql3c24868ExJUv6dVZj2Lro09ldHZUd1iH+A9G0Gd6mPmn4r
         PSv5qupOIvwo8fJsYArDtKa+VGhHcmhjS8602Yfmxt4GgegE6fmCow1v0MKEPSDMH0mu
         EfoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753352459; x=1753957259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5V/D2Qn9Xc4CYsE9C7FqEG9WLu9HNaOPxt769lHd2ks=;
        b=IQmhnvw0oUO/BBn7cmv2Dcb9/GzIVVpceCDjb0bJ53BEp9962Z4QnJieknOn9w1ZCQ
         0A+9U14FRkLjbUZHOcZDZLSZAuv3TAzglrl5vc7h0cmOguPn+Os5lnWYfYthAmwocFzt
         k+m7cZpMeAMFlfOtqH25sa2RW8Hhqwh37j6QrZSKWBiAHURQTV+SoufzWjTlViLuh7sq
         vEIF/vEzEnfeR9Q3BBa/KXeBliAS7D26G5/WnZo7aY/S2W3BEIP1/gDxpUhSIe+qEC1X
         xInFuSM/97ND1Oy6/MrlpFIWhVshYIKK4ZNKJ0MzVbINXeB/rex8R1cj39c/Nb+D5AVo
         DV1A==
X-Forwarded-Encrypted: i=2; AJvYcCVjk39K/3jzizU9GCNtWpbtBT8XNzOqnWhEhHI+6XS08XHX778GzvtMb22+57CpOGkX2iMk9w==@lfdr.de
X-Gm-Message-State: AOJu0YwwNre0TX+N7PctD8YGAcb0/jQ3c4z15KhSledeNL2aB01nDuRk
	YyDOS6Je0rrVp1sPOkVShtb6qo1t3KtUR9xeiBys4kbXskHZKcr2Kqh8
X-Google-Smtp-Source: AGHT+IFMoLrVZFOc7uQ+bl28IBoxZyixEwDVyDlYph47659sPGrwwdAs0tnftYM2rmreV8xdCIcCqw==
X-Received: by 2002:a05:6902:1882:b0:e89:7280:bf8d with SMTP id 3f1490d57ef6-e8dc5b05a07mr6904688276.44.1753352458485;
        Thu, 24 Jul 2025 03:20:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcYsmMNYJTSWnoVpN11PrWK3jHHZc1BwHXn3woP6gPxLw==
Received: by 2002:a25:abb1:0:b0:e8d:ce0d:6ec2 with SMTP id 3f1490d57ef6-e8ddc44b727ls829666276.2.-pod-prod-07-us;
 Thu, 24 Jul 2025 03:20:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJj14Hl35PfZgvgelbnmoHxs75w9qOw3KMy45gntE5yUxkXED5btsJB2/+JpKA5Qv2744fdmSn7hw=@googlegroups.com
X-Received: by 2002:a05:690c:6d0c:b0:718:38bd:bb3d with SMTP id 00721157ae682-719b426a1fdmr86310697b3.40.1753352456908;
        Thu, 24 Jul 2025 03:20:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753352456; cv=none;
        d=google.com; s=arc-20240605;
        b=YV+kGm9lSzvPW+rFYQVg7eFyedif6jlz7kQ/+HHWBCZBFgs1YW2t6HwWvhJrFKNPmw
         4OyRf1z0XZgmfwMRbLP08I8waK6eMJCA14KOSOyoYkSYZ5tFiYRP6vNh1bigphlu0eNs
         WG73hARNo9B96chk1wAlf0x5rh7Yu9KtRRkRGeoV6xxNBIOs4YB1OMHlEOB8O2Uh4Dw7
         pieD9fdVV53k+4GxBb5h6QRVl/L2xUMYjfbt5VKLJcggMLsxC49S5pTs1/tcV86MvVZU
         IIKfhjljX4fMBlurZ9SaRGFqI+/s9e25OtAxMADarN3DGHUo23hD5R/P2a57Gq7xd6mR
         oJQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WYm6W3lhDtWPf0nyR6gtmDQZY04eZ8vBUrCNtxu4k+0=;
        fh=75/wKNTwxewMFC3YGY00FeVavoTLASoe6H5AzKOPvoY=;
        b=HtCuiG9i3OstKNy3KWEaf1JB1WiBHjjkVrd+Se82BE8I9UJnfE8OWwzjbKtk5Ejfer
         aqM1cN6SbCmU0hE3xmks6uvSR1tALshMRQY+gi5vnz5YrqROiwcO9ZXQXE/BDlo8nx14
         43+t4zVTVgVnAN0NZxZwTxW+GWxV1IOtuF33QltB82YWl5NZPtmH4DOl1+ZJIzDxtEgm
         HkWMaX8TZliFwSWeAxGF5bcyrvlrEXNu+fmosQSRTAulFZCI3sc8x9zkDgoPKDZUsJwl
         1X/d7IGOVOHvffXEtvIUrtyCTp0bFzv9cMZXPvaQmv8bUEtv7Vwxx/FpkqCJ8R24340n
         evFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VYy4MeJy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-719cb8dc154si675857b3.3.2025.07.24.03.20.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 03:20:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id af79cd13be357-7de159778d4so75461885a.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Jul 2025 03:20:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXob491POE2rjDVruPcJE5DT3CVWJzgRh7RR8dREJcayOae80d77yNrkdrc2bj3G7BRQRLmKn5809Y=@googlegroups.com
X-Gm-Gg: ASbGncvVvbS1W8qkAmgM5qtJHl/pxd1RpDPP4Owdl5ecKRNmbiXeY2LC6/ynhNHR4/U
	0VdUPD1kwl4IKCyhxFvZxKv+8Ncn58XPP9/C7TRnDuGpx6dNC3l3UyVoZxIqNp4yy9LSFHq8T3B
	1+viXl2MNadDz+Qv/jQfqROaPEymxqQ71efQsg6Pb9Pk9uM7YaD1DmCwv8oZycAg3nDSxF7lUy1
	2sK817A+kcgNzYTetSolucYf4mCwyO+qVStatVzusXnOaaT
X-Received: by 2002:ad4:5de6:0:b0:6fb:33f7:5f34 with SMTP id
 6a1803df08f44-707006ffbe4mr78804786d6.43.1753352456183; Thu, 24 Jul 2025
 03:20:56 -0700 (PDT)
MIME-Version: 1.0
References: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com> <45cd4505-39a0-404d-9840-a0a75fcc707f@suse.cz>
In-Reply-To: <45cd4505-39a0-404d-9840-a0a75fcc707f@suse.cz>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Jul 2025 12:20:19 +0200
X-Gm-Features: Ac12FXzt-IFrliKGU4TwKEp3QLTmaoCdMeEtiXeM1jbFZZjxX2c_7PM9ohrYsnk
Message-ID: <CAG_fn=UnykD8Sc-8dfkFo-UKj88rdk2j78+AcH8fJ-TOJfFQ8A@mail.gmail.com>
Subject: Re: [PATCH] kasan: skip quarantine if object is still accessible
 under RCU
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VYy4MeJy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jul 24, 2025 at 12:14=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 7/23/25 16:59, Jann Horn wrote:
> > Currently, enabling KASAN masks bugs where a lockless lookup path gets =
a
> > pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
> > recycled and is insufficiently careful about handling recycled objects:
> > KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarant=
ine
> > queues, even when it can't actually detect UAF in these objects, and th=
e
> > quarantine prevents fast recycling.
> >
> > When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
> > CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
> > after an RCU grace period and put them on the quarantine, while disabli=
ng
> > CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediatel=
y;
> > but that hasn't actually been working.
>
> Was the "allow reuse immediately" not working also before you introduced
> CONFIG_SLUB_RCU_DEBUG, or is it a side-effect of that? IOW should we add =
a
> Fixes: here?
>
> > I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
> > could only trigger this bug in a KASAN build by disabling
> > CONFIG_SLUB_RCU_DEBUG and applying this patch.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUnykD8Sc-8dfkFo-UKj88rdk2j78%2BAcH8fJ-TOJfFQ8A%40mail.gmail.com.
