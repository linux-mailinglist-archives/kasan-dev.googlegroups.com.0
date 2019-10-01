Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBFVEZXWAKGQE25PAG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B40FFC355D
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 15:18:16 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id w11sf7243321ply.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 06:18:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569935895; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETI1Xp/A00ZfTqlCFVJ4BIIo46OY+jkACGzSYxBqiT6CUs7JQrcAgpqlwpaAL2JRQ5
         /CVTZcihWObn0YYCRwXtbGbqDh09B8rvgacIpcQUOHTXGQOmqTeu0OU4zMVZMFLk3Qu9
         HELSjOccxlC22oy3cj27TqtjB4veX57KzPJzrzZ1qq4w6WQICRdfBlT7B9nvKWdpIvny
         kGZNxleMueTGZUPOr+m8Ewfu/17khS4rgywGCaoXxRNXKmmqLwBPVu/cVhzQrQyas2jm
         5WeKNRSYxdYYfygXu8th2qtCoxA4ZpuTEvdwqRGUW9u0C/n5k7jdQHpL/yWnJZaw2adw
         yi2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=xhyX8xIFAq6XhLfvlG8ZCxkmDcndmw630RooOaNO/as=;
        b=kRdczi21GFNEPjhN9Q19/CkmCUha/Rx5LWQRfCskamVPakkLDkz7TLLegZqxIw5fsk
         ichEbaHRWF60Y9hcMxBd1TeMeC4f+nhUOYh8KxhMV3Tg3Qdune/htIQGt0kVerc0jVNE
         cWvw/qKcnHd/LgEama4Ye2dZ4YcSgQxIgfuNJyUbNh49Okl2USG5WGldpvvuf6LIXCZ/
         R0t41wmI1EApGsyBoMsTkI1qtzmYm2NGU5jjI2ve5ugXc4yhq/OW20ZBoplN+/t3qxXD
         l0X+jtN66XBlb9wDWB34ToGzYLydXMZEkrYmDw/Xq9XTlB2+/UIf5gdfHnGEbtKBGILG
         ss2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=lGp6SqYW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xhyX8xIFAq6XhLfvlG8ZCxkmDcndmw630RooOaNO/as=;
        b=UPYjEIWRujb27Cte9w2lqjVr45ORm+lJUkUt/YC4kT4d9NijYIAmSWx6kcqnATieR7
         ufRs4gF1HeEByhWU43rYRP6uNtcnm9bqTs9SU4mFzXsM3GazHvoKTyP4JvqGAgHt+GKE
         HDLH2QJIl4jeYZQ6GTjDfqEH78gLb2tFHMiWqFKyxl2T7NnVRdryhayjZNxIqQaqFuv6
         /2GjAHhmt09JtTyYpnT3fKnVkX/ZqEQlgdAiiB88C6/BkLh20mvt5EppOQsaDqswI2Mn
         /FJti8zTPMPIintIVHQlnWs732d8d2c8PX2wQTL6pQdRGTh4wp9hMqLF7sernHHxZCQx
         ppbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xhyX8xIFAq6XhLfvlG8ZCxkmDcndmw630RooOaNO/as=;
        b=UwyFyUxGWvr3t80vD3bpdVSG7kJg+UNSfzimAf3K4bjsrmxyrv7GRNYajxSttSIZyz
         i5NmEkYyJRFId2Q93K6uNOlVVmj4VMQ5QFOY2bLX1uqwmqbkkovK6JD0X79FFOLAt2qz
         Ylz17aDRq3oisPTVii+sWQcbBjlyX2O6wmeNOODvBBIX7yLaULM+Dsq6A3ZdcLdwavp1
         rEqkrVNMzCrNovuCjrvyBYzP0sFkQW5rwRNtJALzlC2b/O1330mZImv4ZEBQI+PPuHTu
         N0kN+XQyNgH6Aaq1RCsfJ48R67Ziw74EUflz8aBrHda4njLNlikFiuGB5kQqwS2EBrwy
         zAHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVHrs/jtUOpMAEGFD5N/bAStyOFePRV6bwVGoDpDM2VbzDAn0cz
	jwJQDVhrYKm81EQP3p6RNCk=
X-Google-Smtp-Source: APXvYqyvwkvtmFWmy+HFvLtamhmfmTF+R/QMWScTd7BDzwLqWv+jewSCSgrH4mbpsjU+qo+7kHsx9g==
X-Received: by 2002:a17:90a:8a02:: with SMTP id w2mr5485005pjn.117.1569935894734;
        Tue, 01 Oct 2019 06:18:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f8e:: with SMTP id z14ls189374plo.5.gmail; Tue, 01
 Oct 2019 06:18:14 -0700 (PDT)
X-Received: by 2002:a17:902:6b05:: with SMTP id o5mr25589187plk.33.1569935894372;
        Tue, 01 Oct 2019 06:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569935894; cv=none;
        d=google.com; s=arc-20160816;
        b=owf1H29V504hDHB1CMc96YnP+uZrD5ebUZu9kPfdDVsOycRTDfBF19ynSXGiytkvde
         E1k4A9iXUjmtzMWaAL8g0DkVgt6RfDSjQq3fteDXhkGgTcLP/zwk0dmDx6mxCKD/EuzK
         LfgmlQXXK8vH8qzPO5mr2MMgQTEBWnyFh/9lvkpCHT84+dzlLAMvgPk9YABWAKY4Zxoj
         J+IdqAFuIoSaHd9BgazDXzVVFFK0znNhl7q5NUcnpSk7aiUCOdzwuUXl2n3j8+TFr3WL
         8Sm5QC2Mzz2XiKfB3gej9mGBGGhsBn0n8eTRVyRab96O4Q+W2QqcfuOUuDMOBmcdYCaJ
         52gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=wjg5ezOc5p7km8S342IaUr3A38UGT2t2Rxceh2nlfUU=;
        b=HObrZU50tr8uoAORs6CPnDhshrscD9Z/8RTJtEQtLjLb8L+p97FXnzalwr6Fz5nwJF
         g/gecDps9EyZ/N/LS1aYyRa6MF591dBxsaR4zjyr0XB8MYHKrk/9NvTUsC2EaCks+1tH
         iBMZ+CEhE95YNfUDJ49n5WKmtzFKjZg/AEyrqhWjj3tMfeDvDUQrfaE0uWTm4SMee1I1
         Kp6ifoFhTohMTz8XfnJUIq8IKjVTa7k0mnKitipqlE28uW4LaTQ5kcmS7LiEwVrxrI0L
         WBZV5mU/PGjZ6VrfueSKnqOYfCMHw8pJ9gNPbKnvrKE2Y3Oz7pSgUuHHTwrDlrXvR+Gx
         sYrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=lGp6SqYW;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id b64si649394pfg.0.2019.10.01.06.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 06:18:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 4so11131177qki.6
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 06:18:14 -0700 (PDT)
X-Received: by 2002:a37:4286:: with SMTP id p128mr6108139qka.40.1569935893364;
        Tue, 01 Oct 2019 06:18:13 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id a190sm8443634qkf.118.2019.10.01.06.18.11
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 06:18:12 -0700 (PDT)
Message-ID: <1569935890.5576.255.camel@lca.pw>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace
 from debug_pagealloc
From: Qian Cai <cai@lca.pw>
To: Vlastimil Babka <vbabka@suse.cz>, "Kirill A. Shutemov"
	 <kirill@shutemov.name>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, "Kirill A.
 Shutemov" <kirill.shutemov@linux.intel.com>, Matthew Wilcox
 <willy@infradead.org>, Mel Gorman <mgorman@techsingularity.net>, Michal
 Hocko <mhocko@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Walter Wu
 <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Tue, 01 Oct 2019 09:18:10 -0400
In-Reply-To: <cb02d61c-eeb1-9875-185d-d3dd0e0b2424@suse.cz>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
	 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
	 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
	 <20191001115114.gnala74q3ydreuii@box> <1569932788.5576.247.camel@lca.pw>
	 <626cd04e-513c-a50b-6787-d79690964088@suse.cz>
	 <cb02d61c-eeb1-9875-185d-d3dd0e0b2424@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=lGp6SqYW;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Tue, 2019-10-01 at 14:35 +0200, Vlastimil Babka wrote:
> On 10/1/19 2:32 PM, Vlastimil Babka wrote:
> > On 10/1/19 2:26 PM, Qian Cai wrote:
> > > On Tue, 2019-10-01 at 14:51 +0300, Kirill A. Shutemov wrote:
> > > > On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
> > > > > On 10/1/19 1:49 AM, Qian Cai wrote:
> > > > 
> > > > DEBUG_PAGEALLOC is much more intrusive debug option. Not all architectures
> > > > support it in an efficient way. Some require hibernation.
> > > > 
> > > > I don't see a reason to tie these two option together.
> > > 
> > > Make sense. How about page_owner=on will have page_owner_free=on by default?
> > > That way we don't need the extra parameter.
> > 
> >  
> > There were others that didn't want that overhead (memory+cpu) always. So the
> > last version is as flexible as we can get, IMHO, before approaching bikeshed
> > territory. It's just another parameter.
> 
> Or suggest how to replace page_owner=on with something else (page_owner=full?)
> and I can change that. But I don't want to implement a variant where we store only
> the freeing stack, though.

I don't know why you think it is a variant. It sounds to me it is a natural
extension that belongs to page_owner=on that it could always store freeing stack
to help with debugging. Then, it could make implementation easier without all
those different  combinations you mentioned in the patch description that could
confuse anyone.

If someone complains about the overhead introduced to the existing page_owner=on
users, then I think we should have some number to prove that say how much
overhead there by storing freeing stack in page_owner=on, 10%, 50%?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1569935890.5576.255.camel%40lca.pw.
