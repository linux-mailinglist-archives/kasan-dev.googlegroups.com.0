Return-Path: <kasan-dev+bncBDTMJ55N44FBBDET4KPQMGQECCQIUII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D20A26A1931
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:55:25 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id x32-20020a2ea9a0000000b00294702afedasf4588574ljq.21
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 01:55:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677232525; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+vkYetRS+uB8crEEqb5jsDNjMrCj+jbhYlamZ7nxbMdEYqKLMt3VqstnIuI+Tov0J
         6XbgZyJsGa6bcut3uiiBuNViDNQkC9zn68cLH01I6R6fp3QpbRfYsTNjmjKdiats03cd
         yRI/bqrDF4krWejQeUZ+osr1xT5/DFO01AMCFMrTukcxC3HjxzSR+qXaRxNhpaCP381t
         9bxU+N9yMP0F+6AFDXLJqvkerqL4/jvXpiNovIEppkDjhl987UxdvVf4+yAqCCEa8wcs
         8m3qIcSl4aPBDwhwNncz7FzbBJh92Mp1gfudUAJHLF3NxGACazZilrIO+u+n1E4+wwl0
         IQLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kY2/PS+fjOFBLI4tHV/ZKSIt2L5E6Xx4KfL2ZL5JcDI=;
        b=WznHVFo0UjluevHFKcHBvsLqc+KY8Ga6xlEBqV/o6K8tu9d6QVsljiS3iTi/4Uuiiv
         zTBPomRMmT1hZ6ZdTIFqVt9p4TNWtIlO9vpV861kYI5sI2P8gJhKAHcc86S6cPf3ZtIl
         CBR6Be/w6OD3eSYA38366NF0eLEo9kgligyp8tcP5Q8MJn1wKksZUfPdm/S2BMTvyV0D
         t+1B4IHRKFua6/lFWOt0cfC9GBJmso85ufnDWHP2PbA/JJUwUxeq9uaU/SYjZfpBz+l3
         QFD704YvD3IPzb/njZFeUSMOSV7idObHzDwOPCDdGPDHcNE/iE4tGTXKMFBiy5JnpuEZ
         OFkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kY2/PS+fjOFBLI4tHV/ZKSIt2L5E6Xx4KfL2ZL5JcDI=;
        b=smRFHueV2kDfqWvKawFnp3GL2hiXZyNxMiEKf2CbEIGPLp5E0nauVCYNmJ1eb23m/u
         7hHHGVdwiojcDSpvOv25awnJlAskiUc2zKhE0lXquC9rQz8gz8HQwCm6V+Q9DGuWV7Ah
         ZHtS+bw2hJikzNMLg/nEzpE5XncLMCAUGjRd/4uHM9elixwHD/QYDB5Mv8mMMLdIfi/I
         XpLXm4WhLke9gYuJcyR+/zSC/CVQUW9Td1USNjZGC6kUrbrcCn7JpakQMFf2HlmHV0UN
         Fcvd8s2aTpp7tQs/NApdRICtti7zwN5m1X0hledBl+H8KIqLWiIAkFAVm6HaX4o+7mmq
         SFag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kY2/PS+fjOFBLI4tHV/ZKSIt2L5E6Xx4KfL2ZL5JcDI=;
        b=KGmXIYUXSn4Ja9rOUNCKZM9Wv40hWcKaKpeoU5xHXw6eS9SR2xGR5L+IJVNnJzDTg4
         BHf5o4cjgieAIKQXkp5Kiuhe0xtkpi/WQcQqwqz56hOzqufagdVR3hlP91zZtG0zjH8f
         yWYpiVAVNU9Rc6n9SAO64r/kVhfLWmPuLY/0uSPbdH+BWkil8ILpC+pR/kK8B0zN7QAo
         n+th+VBXPnPLwyEabrAwdcgeHos4oIMAz1EefHu3YKrbTf5tiuVhYg3DKYN5c91HEFKE
         9Oa3/FniRlxgrSGimHX4TBa04uOtj4q+bTF3SruR8F8dRfEuxsyRMOWbeS13s7oc5iFH
         dMdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU4u1P/FM0+FyQHeId2jxZVOSTJLzCZRCrsIGbRYsXh9+kIDMZf
	vwogYl3py5gEPaW+990Zimk=
X-Google-Smtp-Source: AK7set80rcMYWFE8aUGukXrE9xtNXh+NL4ZaXdVJHv1S3tB7j28/DlNwEdR6XSmxLJJdC3respr6aA==
X-Received: by 2002:a05:651c:201c:b0:295:8bb8:e461 with SMTP id s28-20020a05651c201c00b002958bb8e461mr3635567ljo.1.1677232524997;
        Fri, 24 Feb 2023 01:55:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9609:0:b0:295:a3ad:f338 with SMTP id v9-20020a2e9609000000b00295a3adf338ls288719ljh.4.-pod-prod-gmail;
 Fri, 24 Feb 2023 01:55:23 -0800 (PST)
X-Received: by 2002:a2e:8708:0:b0:294:7327:4a0d with SMTP id m8-20020a2e8708000000b0029473274a0dmr5624086lji.20.1677232523315;
        Fri, 24 Feb 2023 01:55:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677232523; cv=none;
        d=google.com; s=arc-20160816;
        b=YBF6E6XBmEpncsPTTERuGSXhsUGvwhyoulrdopfVZtt9BfbU3DZWn5stBfuldZMvgf
         iDlkiNdpnDlo0kOo3eo7H1NufylUt36w1TDguI5mQ9HKRfuAyF/e1+ei4ThMHAkqzPh+
         8Z3AIwUbkfVZgMabKrfUwIQeHeQXjrBc9YdZDKwHAyI2psDl4E0dwE66Wc1/hswIMVX0
         LX3eiQWjCAv4uh2SfGvKDqfantPbhS+mRg1K4QmxEnAO9hxq+XjKwzFbCAZwxQTSDDYM
         mt6x85iMufKtYZgB1q4YuFU2eRm3sZOp/5471rSEYfEsfr8JNTjZ/1J6RBABwa66qnnD
         gM9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=5hKOP+zOtwvtwGqPgrZA/GUj5RgMDSUC85g3TVd1JRk=;
        b=vBPOiySdLstBF83HZGQtezCDTQeUqSI7TJcfHtfP0HNXYz6mf0X3+CRyMJCfkw6oTj
         Rvei9ESvO5VTZ4mGBQLLPoLdFAtnRBLRr4lCu6FRY/zwGE3OjmuH4CjVEb7ZeiUyqDZN
         yj6GxzRbBhC3WT+30MJn5LF73luKfcto0FhfDk1s1qi4oj69D+q2g1PR7GF7J+hXJ+4F
         hMkUxLNJnJVgOWawLWIhtaaEiSJP7dGK1BXcTCeGDFfTkAzGkx7lLiRd8CHd8z6y0MPa
         xIxLf4EFqBOrOna0u59BxuD/Qqbzz/d/IZMhmH7uNplH2ek6DoPfGDmLUwq64Bv++CN7
         M02A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wr1-f50.google.com (mail-wr1-f50.google.com. [209.85.221.50])
        by gmr-mx.google.com with ESMTPS id s6-20020a2eb8c6000000b00295a255ee26si137976ljp.6.2023.02.24.01.55.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 01:55:23 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.50 as permitted sender) client-ip=209.85.221.50;
Received: by mail-wr1-f50.google.com with SMTP id r7so13147184wrz.6
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 01:55:23 -0800 (PST)
X-Received: by 2002:adf:fe87:0:b0:2c5:54a7:363e with SMTP id l7-20020adffe87000000b002c554a7363emr14515575wrr.3.1677232522615;
        Fri, 24 Feb 2023 01:55:22 -0800 (PST)
Received: from gmail.com (fwdproxy-cln-022.fbsv.net. [2a03:2880:31ff:16::face:b00c])
        by smtp.gmail.com with ESMTPSA id j8-20020a5d6048000000b002c553e061fdsm15114349wrt.112.2023.02.24.01.55.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Feb 2023 01:55:22 -0800 (PST)
Date: Fri, 24 Feb 2023 01:55:20 -0800
From: Breno Leitao <leitao@debian.org>
To: Gabriel Krisman Bertazi <krisman@suse.de>
Cc: axboe@kernel.dk, asml.silence@gmail.com, io-uring@vger.kernel.org,
	linux-kernel@vger.kernel.org, gustavold@meta.com, leit@meta.com,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
Message-ID: <Y/iJiCW+HmWZofgs@gmail.com>
References: <20230223164353.2839177-1-leitao@debian.org>
 <20230223164353.2839177-2-leitao@debian.org>
 <87wn48ryri.fsf@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87wn48ryri.fsf@suse.de>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.221.50 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello Krisman, thanks for the review

On Thu, Feb 23, 2023 at 04:02:25PM -0300, Gabriel Krisman Bertazi wrote:
> Breno Leitao <leitao@debian.org> writes:

> >  static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
> >  {
> > -	if (!hlist_empty(&cache->list)) {
> > -		struct hlist_node *node = cache->list.first;
> > +	if (cache->list.next) {
> > +		struct io_cache_entry *entry;
> >  
> > -		hlist_del(node);
> > -		return container_of(node, struct io_cache_entry, node);
> > +		entry = container_of(cache->list.next, struct io_cache_entry, node);
> > +		cache->list.next = cache->list.next->next;
> > +		return entry;
> >  	}
> 
> From a quick look, I think you could use wq_stack_extract() here

True, we can use wq_stack_extract() in this patch, but, we would need to
revert to back to this code in the next patch. Remember that
wq_stack_extract() touches the stack->next->next, which will be
poisoned, causing a KASAN warning.

Here is relevant part of the code:

	struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
	{
		struct io_wq_work_node *node = stack->next;
		stack->next = node->next;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y/iJiCW%2BHmWZofgs%40gmail.com.
