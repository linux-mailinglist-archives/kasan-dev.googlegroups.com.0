Return-Path: <kasan-dev+bncBCF5XGNWYQBRB677WWSQMGQEOY6C2ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 886F474F49E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 18:14:53 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-34596ad61b2sf22482935ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689092092; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ea/rjzfj1EjDVldqzJv7vl58bpspqxfgXJlPT5vFUh6+hw6ipTbRvuBXISEgyAJ/9Z
         92m7sNtPTdgVwOhJEgCN3b7yu9Ebw7EniSv9Eyy5MyhbW7b6TGglicInswiiulAeSBUw
         FI0JRAt5ox22rRHm6BHDHE4DOwHB23j4enABlfSXFnmKw9gA2VXAyZgg9Wzz1Ct2eHZQ
         8JaTkq2uxh+GwNmDo14PAOmIflNmk3D3qC4ISFgIxSzZOHcVxj1aN3g35jCDSi0yJGaG
         Pn3sGICdf2lVSlD23oDTrnWWdpciZ4nIy4E6YwPdcP1CqrmB8aT/3t4d4sL4/LSlXXSM
         jMCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jbIbou3c3ZaS9U/lghtcLeThj2w28LxZE1CAqQndLk0=;
        fh=uVhf7W460rgBYDoMEVmAaCiCt78MDctxX7/FHURrW1A=;
        b=WcuOMvcNF8GFTRM1pi/dPnA4NjycxXwEsTaqF9uE0nFALFKT2tFOBo+piG3Z0kbUhg
         MzTqHRw63qEIZKl6oOQC4EmnY0wOQwNNqVfxMnaQgSpWN/q1xaMQVnVtcey4d5xTSWzE
         eLu14zpLuYT2l6o1OBunyhz79N31WEz2IkmZp4hnxcSfDfIxwXt8r2F0OHjl3D2g5hUc
         EutLoaNT8s/9T3gZ9EKSLZkA6FjcgdvNC9rdIfe6wQuGzG7wMr8tR1glcIlN9SxI3qtw
         WYZXMItN6Uky+Tnx1ewrLAodL315vmqSr+55NGSmoQ5aa+jxXkBpl/CUn01xrVha69dx
         Qybw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JnU40aqX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689092092; x=1691684092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jbIbou3c3ZaS9U/lghtcLeThj2w28LxZE1CAqQndLk0=;
        b=WVzLWTjz/XOW9qjMRs6p/2SZmGQA6dMUpOlU798fuQXosdwlJddTDNM+6LgzLOVvCe
         d6ySPQJ46gZ74ZqxfRCW2T8ghEc3EJKBCGobSv3n/vIS1Hv8DQCosOjC5qxRWOwRMtqC
         y9EPAUcTu8OaJkcNyCk3HVRfejr8NtKkIFPAaMROCM65l47il9KaplX+EtcJav+OsR3W
         C9WuzmRfTwI077kz8jUTcKX9JABTxqC2Zhv0PJTRKX838m3CSxg8YByBLhhyij4ojDcy
         g8I1a7ug82Wja4bfzpbyIpix+DX/F0/9eKPl217RUb9eqfrudyqu90SGO/ZpzfMGsSjX
         fupA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689092092; x=1691684092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jbIbou3c3ZaS9U/lghtcLeThj2w28LxZE1CAqQndLk0=;
        b=gA97xX1o++/uprLLC0/FmpxoLRkc8mCYRrNW0tPgB1pFEIT9M882+/1m6pHbeYA6kZ
         PeOj+uAHSTtcqbeGiiHRdeksOuYRGbjJW7bsTQQCzERzoz+9ymg6EitVO10EUvE6hvrh
         dJgA2TgkQDE1ZwsVx9E2UrZABUAvD9jtqfTfG3HFi8HN0tx+VK+Mzv36NX+sfo/nOXrm
         jMPd3DzH59ebQ3n44z/rpWpw2v0+4xgL7Adcu6aaLbAcc4mgHvNacn+2gdJQJsTifXh1
         yW1beGY6LN8VIrGrggofITwSGTNpWv6pBnZY491pQtF1+YWqr87lxqZqlHsGi/qkUJmh
         igtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLasCfu4aIuBF8+9ZnW4MWAUDDQnlVLnknEsUqkJXhqYcOCt1V/A
	rOpBCHsUZ56J22xaZemYotg=
X-Google-Smtp-Source: APBJJlEi1F7CL3K179WaMv8q11xF7eS001GqDyLYflNLGgT65HJtT9XWY3yYPR7l+BgMWGNynuZygA==
X-Received: by 2002:a92:d201:0:b0:346:5a8b:5415 with SMTP id y1-20020a92d201000000b003465a8b5415mr7015153ily.30.1689092091902;
        Tue, 11 Jul 2023 09:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2352:b0:262:e619:f96c with SMTP id
 ms18-20020a17090b235200b00262e619f96cls3383213pjb.2.-pod-prod-09-us; Tue, 11
 Jul 2023 09:14:51 -0700 (PDT)
X-Received: by 2002:a05:6a20:7daa:b0:132:79da:385a with SMTP id v42-20020a056a207daa00b0013279da385amr1447884pzj.23.1689092090997;
        Tue, 11 Jul 2023 09:14:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689092090; cv=none;
        d=google.com; s=arc-20160816;
        b=FBjA2ipQb1h8wI5zAhc5k2R8xU0wfxnX28IB3k1oekyshdoTGuNmR1IMM2l2DJ+1S4
         05HIRb71DnmWaR1q6ibOAiUq5fSekPLQ6rzjDZALQlx9RFjim/rCF6apmJaJVFD9ItgS
         5zdSjbgV0AIGhej1H56dSdSBuDmStwXFrtD27k+tythgVIZXxzuO47ecQ9dUEFIt0xbX
         Uvp5s0Fw4VSMku3x/1ZjRC609buwRZRf5h5bmpy/REN1XBPxwqCP/d8K7jd93A9q+wx0
         VodyFnlLlVF4hc/mJYXXjraM69LlTAN8i7NZy3o22Ey2Tl9E0XfExxMfZlnxB2BER5b7
         khBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vq9YViWYg4uFChvJGSLE3j7fYiOn1S8zzbS7MgZUOXM=;
        fh=uVhf7W460rgBYDoMEVmAaCiCt78MDctxX7/FHURrW1A=;
        b=mGYhLlKNn763UngPKvOe7kIb7PqS7ZbuQuAa5hv08vKd1fbI4FC709xwQdKSiEUq30
         SejQNItQRpkZaWY5ExJiAYYfmkTR4BnhAVQHhAPOczQTfOvj13r7Ip4QxavkZfhzTdI7
         6MBjzds4XL0u0GaGv4KV/todb+jne4QdQdB+lLh+eIGu1LK/8ASidzn2x/6mWxvpQO+5
         AfenEq16RJTEsM6DCWVogXIpVVdXc83lFWQlMD5ThXJYMprMXCbU5+aGugiD4INO1BAJ
         SKMQ5X2iKlveDsl97IHnp2B80Qv6oFYnbbms2fQ6XaNDTOG6Vsn5aRmBHFsku9OPVf7r
         zkGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JnU40aqX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id ix11-20020a170902f80b00b001b878f9e121si123090plb.0.2023.07.11.09.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jul 2023 09:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id 5614622812f47-38c35975545so5122761b6e.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jul 2023 09:14:50 -0700 (PDT)
X-Received: by 2002:a05:6358:290b:b0:134:e4c4:ebff with SMTP id y11-20020a056358290b00b00134e4c4ebffmr16820772rwb.11.1689092090568;
        Tue, 11 Jul 2023 09:14:50 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id c10-20020a63724a000000b0055386b1415dsm1802755pgn.51.2023.07.11.09.14.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jul 2023 09:14:49 -0700 (PDT)
Date: Tue, 11 Jul 2023 09:14:49 -0700
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	patches@lists.linux.dev, linux-kernel@vger.kernel.org,
	Matteo Rizzo <matteorizzo@google.com>, Jann Horn <jannh@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH 1/2] mm/slub: remove redundant kasan_reset_tag() from
 freelist_ptr calculations
Message-ID: <202307110914.8D460C7@keescook>
References: <20230711134623.12695-3-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230711134623.12695-3-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JnU40aqX;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::22d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Jul 11, 2023 at 03:46:24PM +0200, Vlastimil Babka wrote:
> Commit d36a63a943e3 ("kasan, slub: fix more conflicts with
> CONFIG_SLAB_FREELIST_HARDENED") has introduced kasan_reset_tags() to
> freelist_ptr() encoding/decoding when CONFIG_SLAB_FREELIST_HARDENED is
> enabled to resolve issues when passing tagged or untagged pointers
> inconsistently would lead to incorrect calculations.
> 
> Later, commit aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing
> metadata") made sure all pointers have tags reset regardless of
> CONFIG_SLAB_FREELIST_HARDENED, because there was no other way to access
> the freepointer metadata safely with hw tag-based KASAN.
> 
> Therefore the kasan_reset_tag() usage in freelist_ptr_encode()/decode()
> is now redundant, as all callers use kasan_reset_tag() unconditionally
> when constructing ptr_addr. Remove the redundant calls and simplify the
> code and remove obsolete comments.
> 
> Also in freelist_ptr_encode() introduce an 'encoded' variable to make
> the lines shorter and make it similar to the _decode() one.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Thanks, this is much more readable!

Acked-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202307110914.8D460C7%40keescook.
