Return-Path: <kasan-dev+bncBDW2JDUY5AORBPN53GMAMGQE2AIN2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 898325ADA54
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:40:31 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id u19-20020a056830119300b0063913260813sf5506867otq.21
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662410430; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXnRhyHGS9l3VqvmypGOyek3rh7SsKsUt2t02ua1pAuomocWur9/0pop0wR53TjCdL
         QwqlR1zG4JjuTAj9JvP12iSSBjPOPUSaPydR0MDkEBU6d/J8yNaicW5NxNs1n5Xh8DGJ
         ZJ7O3T/Jry6SPO3+6mLwqvwCLhdNTikB+KNVrez8JAlfuToIwNXWnI9YHhWAZLlhkQCn
         tHVvLjKC94qryc5GOIw82senhVSiC4asWmoTMvPVx6rQLjBdKgZvKj1KbVZRmjxbe7gP
         Q6foAM8pRw5ayUv4m+qCqs++wZrknSHp/0SEjc4VOVkttpC04xGGIDXr2neMZNsvvepu
         jt/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tO9FotyJdHK5ubRrwtsAbYPl/a5xjbYxWklfrRtdges=;
        b=XUKBH+zrLuzDEWf8vVXQClD220i3U5pbja3aOFDB5RvPck9Z+J+y+IohMU1nzPLOpO
         7X/WiaJaHcdoGQq1ZIuyV8+6h5PyIdnGS9cQC7L4tm+g0UZhYcrZx17Tx5LV2f9TSoar
         NlMkCL3ucir7olU+3gMPdd3MkntwdriCs7+a1aoFT9g0ArGlsuSQPKv1mAkgnrANZLSG
         jmMECFC3lmN6LzNfop6bRaY/vuOzo7LwbIbTYiCgDEYyRAqK2rMOJqbPTtKsNPcQosHw
         VkTQUg6Xz2PhraRRJlt8aHxX2NLrvvXaoKwQj8FbvMxEFF2PMhu+09v3GWJbfT+bagDa
         N2gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Hw2xlQvv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=tO9FotyJdHK5ubRrwtsAbYPl/a5xjbYxWklfrRtdges=;
        b=sLkvMaZyMzL9Z6qCIAXr7eR7CH+Jeix7/kW2WzaDW7UCEDk2QIyOdWmhy6XpYuFVIu
         lNOKMkSk87j2Q7yqCKObOeetd+Fm/dZHwH/AQfFnq3+NxaoEbcTGOquA1qa+CwDx+CjS
         EF8lxmUbyWC01MEULx61KuzVbxJdI+iXDLnduAA0vzn5umnGMYHvWWqviBOFis7fumvc
         LM/2pl0cYNFhodCdYD50F3H7e1MosZrj3nXXXziFmOeZviBF+kYOyHaJSiJAoGueQc+O
         voJ0ZlqKpc2/SIhscmIBBVNhMBMOIPsktnNleBVXIJ3ZMUv+U5aSpBK/T0eKC+Esth98
         +HhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=tO9FotyJdHK5ubRrwtsAbYPl/a5xjbYxWklfrRtdges=;
        b=Pds98TWODSm1snbfWTQhTpfFlfd9k9YQorhMFICrEBbI4fWrRsnbvt1P21HOM60zYo
         nnj9l3EHmR/q/O8oMF8Y0aiUXQBZ+Sz2SGYQDmwChrDfXfZ0o4tnnUVN2d1bYTBQr529
         vL8jvjF9pzQfPQ78HEQ5eG2k7ywLlFC4N/YA37P4LfdeTEj238GREV6qolb0qrEQDhjx
         nrAp4qqaZy6t0TfRM29BTj32iBq1uXYRpPkpbryiu4Tym/Hytcg1r2UQlULtN0bSHNp8
         Mzmtlc79F/Ec5y/rm8v/pzl/OZEYaHGiqYJxrEDlOJ2tP2qphMq2RgInqB4mivx95auv
         b12w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tO9FotyJdHK5ubRrwtsAbYPl/a5xjbYxWklfrRtdges=;
        b=F/p72CfL0McQ1Z7UX/gE3I+keyaXsOuJZqgIZXQ0xgvDszWnm/zHhZ46nvpu4Z/zTe
         AYFzWtra0RTBqeue5mJqQkhNX/mUSRs3wmY0vTnxD5fQCAiBM+GINm6FMLDK5PpZdcft
         U6+6VF4RXCm02h4ogeivPsEn/PTY6YpInva7johuw+JvgsWqB1bRNZwIV9TtbB0+KOO2
         zGxkUz/PTIZzqOJsCrwPnfkFAmCe1qzsfwpogvfO7bSAapfoQq3kf95b4HgEuyexA8BJ
         RiljRbyy0rnLP6zWUPB3V/g0Kaa3h/NfRQIouAsksyAOLoACDtoMNshAMqW0fLIxA4I1
         xR/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3ZjtZc8l+C/R+P4eBgx7ZVEP6zYg/ZTVHoZOJATFG49o33kXum
	EEgfBM6isRkh+JDjI7HePpc=
X-Google-Smtp-Source: AA6agR6ssdw+8NXmlcTDN4SJmqDtI+8ShTteZeGVj64TDox9TeG/M/LeMTf7I9TLltLKTy/bw+kiCw==
X-Received: by 2002:a05:6830:6214:b0:638:c7e4:b57c with SMTP id cd20-20020a056830621400b00638c7e4b57cmr20547660otb.118.1662410430014;
        Mon, 05 Sep 2022 13:40:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:24c2:0:b0:61c:4808:5adc with SMTP id z60-20020a9d24c2000000b0061c48085adcls2402200ota.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:40:29 -0700 (PDT)
X-Received: by 2002:a05:6830:698e:b0:636:a515:35eb with SMTP id cy14-20020a056830698e00b00636a51535ebmr20453852otb.169.1662410429643;
        Mon, 05 Sep 2022 13:40:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662410429; cv=none;
        d=google.com; s=arc-20160816;
        b=OiaWzI31CMzZwbvfHDMhWACftifq7EV0Sddl0tZ5zpUSvvpnTF0OA/edCUJnaE0Mn5
         QLnO7xVX6c9GDQpVcdQDcN+dG7thDOVK/sKllIVlG45V6SDXFt2g9a/quNKpzSG4ByRl
         4hMusRTuXICfjwER7rghTJ01++2A08A5VDhA0jPJa3OQU7/b+QgVT/56qWkhSip6Cffo
         aNZwgLsK922FNubg8gVdFJMHu/UxQEuim5IEW1pjE0MjvYTfgg9oJ4AxHaL/fO07qzv4
         ttkm4eCYzPXA4j9pONS+iUGZKTvEunlPcWczX+UvGD4U/kvW89a/fZynw8VpOaBXmQ7w
         KIdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0ypgvZx184oYWrPx4/BvTiSUQeZ6xUOF0aM/4U4hfak=;
        b=qdtYnMJ886n+JJSkOV90zuuVwrSPv0nESGsrCiRwPzpcLt0HeJYwWtdpvT3jU8nUys
         g+Gp2onZFL21LiZPX/dWosFOj92UlCmOf/uoM/Xurg/xnzCqa1CkcbBZm/XF+mk6Kki7
         7IqtbBNG7oWun9L0mq5MZWjoep2+HLFGATWLlIZ6A3/D8/XP3Nn+hY0HDtrFt1ANCY2w
         fOs0A+9tZD3FEqYbzftD2ZpkFQ/LdnHVcPyF0kHf3OLV1XDhYygA7F028f7GxsadDacY
         4x+rKhIECQebrMsnv+xa777gkrLSWN667uDGDVzsSMqj+eVH4tFNF+YG1f/13GqXPO++
         8mbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Hw2xlQvv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id 38-20020a9d0829000000b0061c81be91e8si856307oty.4.2022.09.05.13.40.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 13:40:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id j6so6893978qkl.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 13:40:29 -0700 (PDT)
X-Received: by 2002:a05:620a:843:b0:6be:86a8:4099 with SMTP id
 u3-20020a05620a084300b006be86a84099mr28516707qku.386.1662410429360; Mon, 05
 Sep 2022 13:40:29 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
 <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com>
 <CA+fCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w@mail.gmail.com>
 <CA+fCnZfU5AwAbei9NqtN+FstGLJYkRe7cZrYZN1wtcGbPkqVZQ@mail.gmail.com> <CANpmjNPk13ib57zFzL1rmWiuhZVvS4bmD-yfoMJOYVWT1FdynQ@mail.gmail.com>
In-Reply-To: <CANpmjNPk13ib57zFzL1rmWiuhZVvS4bmD-yfoMJOYVWT1FdynQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Sep 2022 22:40:18 +0200
Message-ID: <CA+fCnZcGM9_H4LJAKj0QSKQ3qX-vF=V_rL_C8xVmaTvW15c6iw@mail.gmail.com>
Subject: Re: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Hw2xlQvv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::734
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

On Wed, Aug 3, 2022 at 10:29 PM Marco Elver <elver@google.com> wrote:
>
> > Does your "The rest looks fine now" comment refer only to this patch
> > or to the whole series? If it's the former, could you PTAL at the
> > other patches?
>
> I just looked again. Apart from the comments I just sent, overall it
> looks fine (whole series).

Great, thanks! I'll put your Reviewed-by on all patches except the
ones I will change in v3.

> Does test_kasan exercise the ring wrapping around? One thing that
> might be worth doing is adding a multi-threaded stress test, where you
> have 2+ threads doing lots of allocations, frees, and generating
> reports.

There's probably not a lot of sense in adding this test: this part is
tested during kernel boot. Even with defconfig, the stack ring
overflows multiple times.

I will, however, add a test for a complicated use-after-free scenario
to make sure that KASAN points at the right kmalloc/kfree calls.
Before I get to implementing [1], the report contents will have to be
checked manually though.

Thanks!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=212203

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcGM9_H4LJAKj0QSKQ3qX-vF%3DV_rL_C8xVmaTvW15c6iw%40mail.gmail.com.
