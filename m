Return-Path: <kasan-dev+bncBD52JJ7JXILRBQOGWGPQMGQELOIVX3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92A6F69757E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:44:51 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id h5-20020a170902748500b0019aacd1fb04sf3171002pll.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 20:44:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676436290; cv=pass;
        d=google.com; s=arc-20160816;
        b=qdlqCtojojKb+NbfFKXeBEXEDrliWrp1ycB5LMdVjhTEKkSFbIxmkiO1L0LjHE4r1F
         BtuRutdmWYEuS3NaVzCMvTy6CT1RQhMYTeqJnWpxxEKHwoQ9ol4PPs7NqIfS/hMCichr
         08ORht7dhfns5WvyX5Mlg3eDguc1RqZl4UOvHNCN905zPLEEj8FY4nTDj8ZU5TylQcRV
         yixmXJQB9Mjk8eOM6XUl3dG6+iASDW5haTDkrlizCcivv5Gkd5xEIVRwzoZFTIHQR0W0
         l3zygdUBZXgt0PgbLFPcL/vTLnUhvezTVNHlP7pRDvyGplLaflnVB0AbqHfbsqxtah9o
         zLEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FK3UupoDNAHVKdeaY4Y2xyu+qnAI/InMWhaG8R2M2Iw=;
        b=EfYsT17rzoQNkkf3LuQWT1Qo1+nfo+Bg4ltpCWzfMqrHGt8i8bQkV2SM4N/fLpab3L
         hh4OPVxHzLQOzmn90C1ORcjzkAMT/U6TS8Hr5RTsyGqF14ZR3e4ZmiBVF7bALj5RFAEH
         HXOWIRY8wTCSEVtiyZRNia70uMMSMw6I8AaS66ONMO8i9C+lIZqEgYC4bV3zsrsF/c17
         rLmIR8gwL+XaivLxxIszQZKPr9uv+EOtNlosN9oMTQPQmnUClIb+sRn+cCGKquPo64aU
         yp+BnTtOtk5tf/v3kanPQXr187cY4+CqsQ5BzhcVX2A/wVcuUF/bgAiRLvuVvzIPzS6O
         ID8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D2G98lGO;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FK3UupoDNAHVKdeaY4Y2xyu+qnAI/InMWhaG8R2M2Iw=;
        b=cpF0xzwqBR+0ZjXPtb376QQz48/st+GKyNOq4wTlK05MUGVZb85MpI0dhVCvOxSzgK
         n5zabKadZ7q+jSkrfZ/6c1jjZL8ufaQlqQHPPe5V3BVe0BzMKBrg7jYICkLvQ8VmutS2
         Jc3HU+roG09Ld7JAwnncnZ5CRul6owB3JttLzQ5gcPJQkpWPHWP7+V8lzGFp/QtLXUfS
         +9o97bQIvnQafa3BI4Ys7Z/gtSoMvg9zuHo6QZxfgc95wb+UOAe9p6UYp9WCXE+mCgJ3
         NGkaETQ+wf8EOSmx1K8MBBT/BymJVZvXbyOZhpWAyUXE+IsJXl825+Ebk7KFEu/Zw0rU
         NOiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FK3UupoDNAHVKdeaY4Y2xyu+qnAI/InMWhaG8R2M2Iw=;
        b=xqCUukVwuk8Jut/kMJco5OmNkjKDafO9uwhZ98FWmxjR0Rlk4hhp3QUHNeQ+ayy4f5
         +foDIpxnJ0Abx29k++rypMqD5cmFGoXBMoeHbDzWbloha0/+kiNQHZqrZ+Wt7Dk1PzzM
         SWWuVGJ+NxoTMp/XDx5tsY400nofy0P6Q+rpn2Tc2Ctr+AtP+UZySqi7EdxmGnxy2ZA2
         XoZ1bfmTr0tG57rjxROiEFBIOrmWtroIr8wBF7TFCD/KuRkpsqFxViunwFk8oRMBqZWA
         HKlKxpngX+S0gesShw9zBYCEpNAwpsQpHZ/P4akdFyyAtwptAQMIhQLgc+bordZh/v5g
         j+bQ==
X-Gm-Message-State: AO0yUKWqNRVgWGsI6/xlh/Z7Cg0vD6odHGay2Z4y8PV8TOag2APL7MY3
	9TzewJPh4vH7FOwC7rPtbG0=
X-Google-Smtp-Source: AK7set/Hq2c7f7tR7MhCcgK0qY5HUZKAxOAJSrpXvyfQic+lbCkOHSFErskjTmwa+SE+3ivApkVr6w==
X-Received: by 2002:a63:291e:0:b0:4fb:9d9a:9b41 with SMTP id bt30-20020a63291e000000b004fb9d9a9b41mr124363pgb.56.1676436289944;
        Tue, 14 Feb 2023 20:44:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4c88:b0:5a8:e06d:9470 with SMTP id
 eb8-20020a056a004c8800b005a8e06d9470ls1021697pfb.3.-pod-prod-gmail; Tue, 14
 Feb 2023 20:44:49 -0800 (PST)
X-Received: by 2002:aa7:8e88:0:b0:5a8:d97d:c397 with SMTP id a8-20020aa78e88000000b005a8d97dc397mr505385pfr.24.1676436289106;
        Tue, 14 Feb 2023 20:44:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676436289; cv=none;
        d=google.com; s=arc-20160816;
        b=cmTWUe+zqEE8Eh7cost5QxGZ1cH4qW5SVf10o2WElSZgeQz6sVA5LP8Da3RuahT3aA
         VGrrUo6nTJ2nNqzag5dXjSscnsFPDbGVD5g2ywyUszPq2zmdyqesnlWaxYfmP5dnFnnz
         jBlbc4EpFylmJ0eA3vjPAkgthnnrX6PD0+AvYvNPKV72SMgg4xBznzeVeXbs33aDeiq7
         8FuzgorRPNpmWCQJHzWAFlfWuphBUHuhhWOtdC5pz8TYgB26bHDLeawULPEngZ6slc4c
         ljLet9Nqx4YnrHHwvKATOOw2DueVvMWuDq8WOwup7MR77MSg352SxGyqBT2zO7U1IC6g
         pU1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aNl+bTrdiuBtPF/dZkoqbIPBqUd172UM9PQytiAg0FU=;
        b=pMQDHo6OEWMrRFJD3oFuRG+m8zvQ2Tw4nGldGht+cEEBM2gyHp7RAD3qgrEo+F+7oT
         ON6TuEgSuojCj966BqxIwt3Wbig0Udwq5NiSNMueYd745V+NdnXvlX9bC95wTwmtLuMq
         PtdrJcztLTjXXGntuIMd79BxUuNWJQmJFkhcFg5TXAh+yOupqES8f/5nQE/pqvhkbApC
         WQTV2rFIh+zJtu2QmIVZHrBkDqfTn0i0MNTDIDn4eTovv2nuNSW/d2FOLYk0/LiTVWog
         bCqatPv1j2W+meobefJ2Wkz0Hjtd2dXMfxpWrTXaq9TaYUKyifJYwhOaOSvbLOnywP+I
         lvzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D2G98lGO;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id h5-20020a056a00170500b005a8bfe3b24asi515079pfc.3.2023.02.14.20.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Feb 2023 20:44:49 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id c15so5497521ils.12
        for <kasan-dev@googlegroups.com>; Tue, 14 Feb 2023 20:44:49 -0800 (PST)
X-Received: by 2002:a92:8e04:0:b0:310:9d77:6063 with SMTP id
 c4-20020a928e04000000b003109d776063mr318042ild.5.1676436288254; Tue, 14 Feb
 2023 20:44:48 -0800 (PST)
MIME-Version: 1.0
References: <20230214015214.747873-1-pcc@google.com> <Y+vKyZQVeofdcX4V@arm.com>
In-Reply-To: <Y+vKyZQVeofdcX4V@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Feb 2023 20:44:36 -0800
Message-ID: <CAMn1gO4mKL4od8_4+RH9T2C+6+-7=rsdLrSNpghsbMyoVExCjA@mail.gmail.com>
Subject: Re: [PATCH] arm64: Reset KASAN tag in copy_highpage with HW tags only
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: andreyknvl@gmail.com, =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	linux-mm@kvack.org, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com, 
	will@kernel.org, eugenis@google.com, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D2G98lGO;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, Feb 14, 2023 at 9:54 AM Catalin Marinas <catalin.marinas@arm.com> w=
rote:
>
> On Mon, Feb 13, 2023 at 05:52:14PM -0800, Peter Collingbourne wrote:
> > During page migration, the copy_highpage function is used to copy the
> > page data to the target page. If the source page is a userspace page
> > with MTE tags, the KASAN tag of the target page must have the match-all
> > tag in order to avoid tag check faults during subsequent accesses to th=
e
> > page by the kernel. However, the target page may have been allocated in
> > a number of ways, some of which will use the KASAN allocator and will
> > therefore end up setting the KASAN tag to a non-match-all tag. Therefor=
e,
> > update the target page's KASAN tag to match the source page.
> >
> > We ended up unintentionally fixing this issue as a result of a bad
> > merge conflict resolution between commit e059853d14ca ("arm64: mte:
> > Fix/clarify the PG_mte_tagged semantics") and commit 20794545c146 ("arm=
64:
> > kasan: Revert "arm64: mte: reset the page tag in page->flags""), which
> > preserved a tag reset for PG_mte_tagged pages which was considered to b=
e
> > unnecessary at the time. Because SW tags KASAN uses separate tag storag=
e,
> > update the code to only reset the tags when HW tags KASAN is enabled.
>
> Does KASAN_SW_TAGS work together with MTE?

Yes, it works fine. One of my usual kernel patch tests runs an
MTE-utilizing userspace program under a kernel with KASAN_SW_TAGS.

> In theory they should but I
> wonder whether we have other places calling page_kasan_tag_reset()
> without the kasan_hw_tags_enabled() check.

It's unclear to me whether any of the other references are
specifically related to KASAN_HW_TAGS or not. Because KASAN_SW_TAGS
also uses all-ones as a match-all tag, I wouldn't expect calling
page_kasan_tag_reset() to cause any problems aside from false
negatives.

> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/If303d8a709438d3ff5af5fd=
85706505830f52e0c
> > Reported-by: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.L=
ee@mediatek.com>
> > Cc: <stable@vger.kernel.org> # 6.1
>
> What are we trying to fix? The removal of page_kasan_tag_reset() in
> copy_highpage()?

Yes.

> If yes, I think we should use:
>
> Fixes: 20794545c146 ("arm64: kasan: Revert "arm64: mte: reset the page ta=
g in page->flags"")
> Cc: <stable@vger.kernel.org> # 6.0.x

I agree with the Fixes tag, but are you sure that 6.0.y is still
supported as a stable kernel release? kernel.org only lists 6.1, and I
don't see any updates to Greg's linux-6.0.y branch since January 12.

I'm having some email trouble at the moment so I can't send a v2, so
please feel free to add the Fixes tag yourself.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4mKL4od8_4%2BRH9T2C%2B6%2B-7%3DrsdLrSNpghsbMyoVExCjA%40mai=
l.gmail.com.
