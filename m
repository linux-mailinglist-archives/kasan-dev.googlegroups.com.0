Return-Path: <kasan-dev+bncBAABB3HO3PVQKGQEL5W3AJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F63EAE1D0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 03:07:58 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id g15sf11810138pfb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2019 18:07:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568077676; cv=pass;
        d=google.com; s=arc-20160816;
        b=BzSAd6v4udc/v9Uujhwa462nFIWPm37cL/6AhlLAbfPdsHXgwYYyfccdgbRQySWgaP
         cUJmZeUmypXz2xFvoQONQj5k4qF6D0KO4f2DA/4bnjfTMg2fVxEHI6+6P/o7tswJBWc5
         pd7zyU0dzujqoeLXoQ4/PQMRJwAk5ryHKhaN3EqpF3cvniUoIjLbtTJLx3U7nRuI90h3
         KaH+czMd6tw23I5fqzZmSMJxnxUSZugU396pQiC7l6ZuJG/TSzJ9Re5ld2WLmvF+/Xic
         OIU18L10uqRc6ZUIwgRtwWxWHfxtmjq6d4r1sAeh0Tv3PFwV37QIwQryq81QvrQFOxEe
         DZ7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=tehRQ+I6cAoRWrUs8i6d8LVXVu7+sz4rJbfSxZHP524=;
        b=lo3fmMaqKVlLUqvAVE2FoSbFQxtXzBYTfBwS6GZFiEQZK0YqIfQCe86zi0e+5PkBXu
         ofNr+c7jX41iTppPDKOKvUidfqo3vKXNPxocHirF2GPCAXUUOTKhNvsxFQi4uX6wZPKy
         dpAb0kESdX+614kciqYfaO9QJqG5R7y6k55cvVHav9g4JxQh/hNFF0yughzp0GR/sRgp
         sp4zpUvijtG4oyJyYRqH8kuq6UooTGKK35aXD0TXR1G452/9ZtNFvaIAZFLKq/DLfWLP
         rNbPu/I3mcPj2Xj+blhNEAma/SpHZGBLQ98KgkVMt5gkBYOzsWo0Xm+4MwJ8ZPnUg8dE
         lXuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tehRQ+I6cAoRWrUs8i6d8LVXVu7+sz4rJbfSxZHP524=;
        b=Udqp3+I+h/0p3Vj2BmVqGXN8py9S617JSZ+V8fSAVyAH4OzpFCUdHNYDeZmhSWnp5k
         BhjxKfwlQSPIQyB7uhXNVGS7kz4CQLFqUWywBI72A6IwfuxIFpqdEFk1/bpD2qQ79OZ2
         +MV+Apu3pDn2PTI40A4TvDDEsiEkgfO/eYUFNHB0rMfpdSLvxtf2Tt5ismTs/H5FTHlA
         LLL5uef6BPgzhckItA3KmT0eVxAHbzy9FBr9RAbJLaX5E8neB5w1SLL19sCvT6mz1Vqy
         eq8q3rYsxePzwPG47qrz3b8X5eIjRmL8ed+0hk+A/Zw7y3/GCwmaa4zTytN/dWQOLq+r
         Qy6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tehRQ+I6cAoRWrUs8i6d8LVXVu7+sz4rJbfSxZHP524=;
        b=sS2GqFceR1TSkSqZo3fXjW+t3TF0PcR84Xqf7foaV5MEe3zKz9SF0vf2kE1eeYUAx1
         kK1b0izv3MZLNph/F47/dTFlMgG97kklARA2Ba+UyhMGorgCINPaa0RMo+IFVrconJje
         rCCmMbXuJnnVLYhnh5Q5EWfAV80OiutIPOyNbChYD7lKHi7ieMmpchrY5Kp42OdbUBVZ
         Wern0u0RzM0WgphLM5MBUqsnqImOd2hapLspgG3RTRbFeweHRJs76HyAAEVmKmmTIrKV
         msnKiLxB8Z34t03XWLdxxeIMp5+eE0ta3+RRDkLTM1khPYkmk8yO3s3NBcB5m4Cfq1Hf
         M9Rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXarlbUgAKqsCPKN4/RlBlfdVoS88ADjmPsThPhF1+2/QCaHlWG
	NCSpBjGgiNrX+3U5KHNLu48=
X-Google-Smtp-Source: APXvYqwX6VTRLwVbFQ722mJLX2cA+J/1gm/Cqak0sFWHQFX3bJ5cDXgWjn1R5IsUiRieqmdpPyyPWw==
X-Received: by 2002:a63:db45:: with SMTP id x5mr24578646pgi.293.1568077676263;
        Mon, 09 Sep 2019 18:07:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:45cd:: with SMTP id m13ls3231015pgr.3.gmail; Mon, 09 Sep
 2019 18:07:56 -0700 (PDT)
X-Received: by 2002:a63:3fc9:: with SMTP id m192mr25153735pga.429.1568077675897;
        Mon, 09 Sep 2019 18:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568077675; cv=none;
        d=google.com; s=arc-20160816;
        b=DHIRk4qeHf/jSVGcvmL1AJKDl5Me4ae40ue8uPaTK4ndFV7jJWALAwFe0kUWmUKvNd
         ckvacFK4kqblQYUjZPEly/akN4QYAbcoPhFAEPLrGAw0hm2aTKW09VWYe9cZCtqJMCpf
         pTOGWYenTZ+Ls4M4DVdycq+G/TOpPBXAR674H7ITJhV5kUhaKTnAGcJEOVmwp/v5STJe
         8LNcU/ifEkZp6NDMmg0PlKd6lUJfr43VVL6YUdW0XsSTOhgF0k5tiYMBth/f9BhNJ3gr
         3ip3PFRDXMkwyQfjMabo9uj49zUzUEwnagkcLpoxyX+6+Rcq02JAk0SfmV4oNQc7jnwF
         bKLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=HpkXJVsSQY4+CyX4GWsni62ZtKoO3xWySGTQdLp5Vp4=;
        b=WEx+1C62+u4swc5Q+mIkdrHBr0goaRe2BYiEFBjLPIm2zMKfDEB6J2Q1Zmre2AmYMu
         YJmzInU5BjxC2p20ZQ1kKobcH8uFmxiS1fggYGQljfD4/FImpTiVlXDLRssD3Ds7sZqh
         4md/gFezX5+4msJCGy0IXQdOaGoKAMDam6RHSAH/y8Fqh481UPXrPeuWbqFG2NEIuEP/
         xw/hXiBgkp/zVF2KawcnaUPkeGLGLhYyfZYAxoRJS8/xIi7L38JBJB8WnFf/FyKmF9aS
         ye4ZuFaER6iRtpTDoKI2GdRQFN5UGVx/txPy68TyKqpjy44rOaoct3czpwGWDc0LBXrj
         /r0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y8si4349pfg.2.2019.09.09.18.07.55
        for <kasan-dev@googlegroups.com>;
        Mon, 09 Sep 2019 18:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 36793eb043954315b23be36aa610228e-20190910
X-UUID: 36793eb043954315b23be36aa610228e-20190910
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 831663314; Tue, 10 Sep 2019 09:07:51 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 10 Sep 2019 09:07:49 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 10 Sep 2019 09:07:49 +0800
Message-ID: <1568077669.24886.3.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/2] mm/page_ext: support to record the last stack of
 page
From: Walter Wu <walter-zh.wu@mediatek.com>
To: David Hildenbrand <david@redhat.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, "Andrey
 Konovalov" <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>, "Thomas
 Gleixner" <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>, Qian Cai
	<cai@lca.pw>, <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 10 Sep 2019 09:07:49 +0800
In-Reply-To: <36b5a8e0-2783-4c0e-4fc7-78ea652ba475@redhat.com>
References: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
	 <36b5a8e0-2783-4c0e-4fc7-78ea652ba475@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2019-09-09 at 12:57 +0200, David Hildenbrand wrote:
> On 09.09.19 10:53, Walter Wu wrote:
> > KASAN will record last stack of page in order to help programmer
> > to see memory corruption caused by page.
> > 
> > What is difference between page_owner and our patch?
> > page_owner records alloc stack of page, but our patch is to record
> > last stack(it may be alloc or free stack of page).
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > ---
> >  mm/page_ext.c | 3 +++
> >  1 file changed, 3 insertions(+)
> > 
> > diff --git a/mm/page_ext.c b/mm/page_ext.c
> > index 5f5769c7db3b..7ca33dcd9ffa 100644
> > --- a/mm/page_ext.c
> > +++ b/mm/page_ext.c
> > @@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
> >  #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
> >  	&page_idle_ops,
> >  #endif
> > +#ifdef CONFIG_KASAN
> > +	&page_stack_ops,
> > +#endif
> >  };
> >  
> >  static unsigned long total_usage;
> > 
> 
> Are you sure this patch compiles?
> 
This is patchsets, it need another patch2.
We have verified it by running KASAN UT on Qemu.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568077669.24886.3.camel%40mtksdccf07.
