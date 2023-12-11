Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKHP3OVQMGQE3IC5VRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D151180C87A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 12:51:05 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1d0af632728sf2743795ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 03:51:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702295464; cv=pass;
        d=google.com; s=arc-20160816;
        b=PxP6we9x8kyr5/iSPqMW27KcQKH7tV0LnaQFVkaCCcMXKn6OobVtL9WvNrpKikr3dd
         v6SdJsymNfjosd9JuyCP8lcXmLpj+/lkf4tMKcMjn1UmOM5sJoSz86BHfJvkz4U9RzSl
         HZvtWh0BIU2QNk2DrqvjO5YPfkx8zzH/w3rOi0OxKSK0BDupqW6dlqXsVcAN0Odpmjzd
         rcUFPGwuGxrCS39aBQKCjiTt5thhHOunoRqMEiyKwZqYjDhF0p2Xqq6j442r9rgUfuDg
         8Oqy8PBxhqu4CrCd52H4fqxLph2m68lG0CwLEr8nVVDt/tZ83gvIqTLTNc+hycBLouyl
         mNAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qIawe9qm2XwifuSRok8g9GJt5tCOLm77hDsdhfjtC98=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=Lnv6JjYk2ekJxIQagCVhccw+ouwAzYBCol2f5nZJvWAAUsGJfg8uw1V9JTtGKWkZ5Q
         JQtS8WzDJdvB0bkAX+eZFfdfbKNqE4P+ddapLQ+gJwzAb26EqfEJNjEnSiJy42uM2MYj
         LvpKu0teM/Evv1KzCGrQKd9OCoayXqvfXdfYeCqnrXmrE91rdWPNNQuvnkILmLCVs7Lw
         Gi2vu1rI/LfprKXmBKhKZ/femo0dKnXp2NxjnQ77ep0x6N6HXpvzzYd1pB8agKgfQqR7
         ION3XaV1No1PlkEk6PSm6M5rAOZ2f3BlQ6quogyofzu6ZXl8weqvZtGIESw5kgbiaJdQ
         xxNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VLHXi438;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702295464; x=1702900264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qIawe9qm2XwifuSRok8g9GJt5tCOLm77hDsdhfjtC98=;
        b=Xdxy0z1Rd8uQpibsV2p+kdPcc649dsoXerY9/c8tSZbzSL4lAztz3t59EV9GGtTEQX
         R9+YjIZmxXv7gbf7CWgB2xkYgB3/PCH//C91YOiRtvoFf+9gLkFk/tIgLjqKZQJQsm87
         p9lrZaBucMeuB4sv6w07dquDoWx22fqHb0ulFFfHOeMGaXOvlBUF6eZ0JcjEd9l8C/B9
         81mTEMkmVtOuCkAp9ahiUFwwbQS5kZXFe5rE3wHC9OMSe4dYiI7MCqR5+HQNIKbHELdL
         /4zuWBqG2KA03Fgheng5STbm/eVVEWuLb5WEUZVaua6ol/ytQUSiFCin8CdT/KpT7UJz
         qZUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702295464; x=1702900264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qIawe9qm2XwifuSRok8g9GJt5tCOLm77hDsdhfjtC98=;
        b=oi/eSbGmUCbgfelEUxraszGZCyMBlir2NU0wStMOc47nvVk8JQ/EicbBwy10grSWLB
         xo8qM2Q6xiCozUIz0gAPbxkmkm01xSwi0YvI4wlQ7C7TnIv02dSxKeU2mFacU40QEbRb
         xXJETu95rLguIbaBTPHo+4t/YldgnAHi4QaxECAlNyhZIsY1iimwSnB577ut9Qp9Yo2Q
         0bvvILVXuBeFlYABHWrorKtjK8AtjJM8RP087LJT+Xp7cCACgSv0ucw3eLoWyb9IPugC
         7dl+lgTMk02DjRPlnKN2BVg8JrdBky/WI74XRdXMt/UQMTlM9Jjw2kLjHLpP7OWHtVJG
         LDKA==
X-Gm-Message-State: AOJu0YxNE/iCEdd3xqXCxDr7RuqYSOxgwULA08Z23Nz/DcSc9Ja1hZGs
	k/j4ctBZ3fe0o8+ZyU4ZcXU=
X-Google-Smtp-Source: AGHT+IEpVn31niGSiMDPIgxk7Zx3ll6upaA5iYxKCE2VBhqDBYE5tBBb0HKPr7GxpygIsU1h7sVaHg==
X-Received: by 2002:a17:902:e5cf:b0:1d0:435d:8574 with SMTP id u15-20020a170902e5cf00b001d0435d8574mr494404plf.28.1702295464332;
        Mon, 11 Dec 2023 03:51:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:161e:b0:58d:be41:d2a3 with SMTP id
 bb30-20020a056820161e00b0058dbe41d2a3ls4252766oob.2.-pod-prod-01-us; Mon, 11
 Dec 2023 03:51:03 -0800 (PST)
X-Received: by 2002:a4a:6701:0:b0:58e:1c47:30f5 with SMTP id f1-20020a4a6701000000b0058e1c4730f5mr2084975ooc.18.1702295463717;
        Mon, 11 Dec 2023 03:51:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702295463; cv=none;
        d=google.com; s=arc-20160816;
        b=ucA84FWeSMv3MhMw2IzEliEqhz2LklIRx1KXReqIntsFU4BZDFjIidtbGBXP2graQE
         zcuCk+Lp0RVBIjYi5v2NvkzBBdopD/FhWsyDKe88XPFapxXxlsajtIAGMN6mypADKi+e
         iTlurjGUYZmK0YJHKTIb1wt/j30Z0yHYOjHpOMPY2HgPJ2R9AoFpgR1sVNVYQhiPvQSz
         3tH63t16THJjYi0IgMzK6DfGsArWivZPXqMa3j7rAY3RJLSYIYNucIFaDHfWlbpgB+Du
         L+6uEENBf7qZx9LxYJx8suY4KhTfdNrf9uAdQc6WHIm0bn20ZHhQUW6oSyLVWiIaz/Ld
         u6+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eFlOaOKOFTUGeU3hihhI0E9Jv6p6CgBMgpCcvHMWbLI=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=MAMRrOc591BCXGHLn6k7Dw4wElbVIwZSkI4b1cMXcSzjZloJUTjZSE3op5s7RlBgT3
         bnTsXMmT7p9vj1yGIIU98z4W/R+ePhJWiuWzHS83n3xts935T1Rg+n5OSsrMMsecApl0
         7mnT3p+3RTZZwAEwpQEK1nIpsoCv2NUuocpiv/4NlmVAE6BRpm+4za6xjmMHhxQMLE9B
         6VSw2Bhphkp3nNXAPwRIIV4k1tYMVCGNbdU8v33scCt1BbpSvopmlJczdKyp4ghdKRfM
         m6gE9LQ86LiZeyKNNI+WrQBOi3RfWZ6TfGED3Ppq31sTuWoeubkMWETj0+MX0tuWhlP/
         nZew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VLHXi438;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id e84-20020a4a5557000000b0058ddf7336a4si1051490oob.2.2023.12.11.03.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 03:51:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id af79cd13be357-77f5b3fa323so137397085a.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 03:51:03 -0800 (PST)
X-Received: by 2002:a05:6214:2626:b0:67a:b923:6ae2 with SMTP id
 gv6-20020a056214262600b0067ab9236ae2mr6255559qvb.23.1702295463057; Mon, 11
 Dec 2023 03:51:03 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-13-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-13-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 12:50:22 +0100
Message-ID: <CAG_fn=VaJtMogdmehJoYmZRNrs5AXYs+ZwBTu3TQQVaSkFNzcw@mail.gmail.com>
Subject: Re: [PATCH v2 12/33] kmsan: Allow disabling KMSAN checks for the
 current task
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VLHXi438;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Nov 21, 2023 at 11:06=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Like for KASAN, it's useful to temporarily disable KMSAN checks around,
> e.g., redzone accesses. Introduce kmsan_disable_current() and
> kmsan_enable_current(), which are similar to their KASAN counterparts.

Initially we used to have this disablement counter in KMSAN, but
adding it uncontrollably can result in KMSAN not functioning properly.
E.g. forgetting to call kmsan_disable_current() or underflowing the
counter will break reporting.
We'd better put this API in include/linux/kmsan.h to indicate it
should be discouraged.

> Even though it's not strictly necessary, make them reentrant, in order
> to match the KASAN behavior.

Until this becomes strictly necessary, I think we'd better
KMSAN_WARN_ON if the counter is re-entered.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVaJtMogdmehJoYmZRNrs5AXYs%2BZwBTu3TQQVaSkFNzcw%40mail.gm=
ail.com.
