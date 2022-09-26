Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEW4Y6MQMGQE2OG45ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CEFF5EAFA6
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:23:16 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id x1-20020a17090a8a8100b00200a805fba9sf8125718pjn.7
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:23:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664216594; cv=pass;
        d=google.com; s=arc-20160816;
        b=nZvVJSCgkJYgHCrHDVbwWFRfaKGep9mBdc4eof3GZ1yK1ClqbAuiUUgLNqUhdKlqe3
         /ofLOhLNiM5Cm8UvY3PTQagkr86JqZAH0SvecRQHSANqGjkdoSYYLz4BztUUIMcsx75h
         G82uBr/L0e2y+N6lDpLYIL/9mYH6rLBxkX1SgqJ3UQYYrf+VHtHjLhdjYAfW95GezLgg
         hrb6j1HvTGUjRj36ksrdciZwkZyekW6W5/QvGrqwceIWgFZwBgDkdCa9VXsj6vGquEUD
         weJtxRLMUDgDMD5JG+NyxEmZ8I+tgepubC9XQmC1TKPWjtcfwbJtIgaJrsfs0YlqNNh3
         o9mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NKWfXKKShqQDx3bCG0ljyCthWe3ze1hEvDobTeuedSM=;
        b=IN1hzuFQ6WXFJVLa6/R9CxaJ0Gn2lFTJH93JDWFkNofNFN+kUURhZDBZwNfZ1oCrt4
         m3RgV/CSZM9ULkMcSRfdsn/VSYXlPa0khB0VKasx0zsygHPuyQy7Bv2OvsvcFP4eFOy+
         95NhkB8m9SjZMZC/CBjj5l/E5Fb/Fs6J6I6lnTFbo8AAKZjWkF3acdpySiJzgQ3vzrCH
         tszCcy0IUL9Hlgur0e85ckDuNx51x+7rkCqikn8Kj5ef10ZQMpaXv06hJkJmv7RAgoSW
         ylLDLDsFvm31u7c8VtJzGYoAAhqX1gtsfj09XR3HCUPqrsneBbOZikAIxPDatUC2QQ+X
         lNCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="F7JV5x/0";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=NKWfXKKShqQDx3bCG0ljyCthWe3ze1hEvDobTeuedSM=;
        b=FOb0evc0Pczzp0B+LybmnvCxuZTFN3q8Yf9g+zgxNbiWMKBCcZLYthceHQUgyIT+z8
         gVh6QrQgyJYD0YZXiplz/A/r95Wu3LJs6+d1N40B+Av3hlBDTbmZ3UotlHU+y5Lv70Vs
         YpTcLgUxQv12qPB3OXwpLuusQ19qfNv0mjfB0VSPxFLv8Ja4sJDoxFXFwfY+b292TRjT
         xOEbCfn7v674O6SSYuw0iPm+BjzGXycJWSuODTbo7ojMv9DNJeDR0m3cjujJiBTdhpET
         l5RCkaqwe0DLi/fYIFmt9Y00pmvSQQGd/T2DQIcejFueABuwcuPbhVyzag8KX7RhPFZN
         T51w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=NKWfXKKShqQDx3bCG0ljyCthWe3ze1hEvDobTeuedSM=;
        b=iWx6G3K96CHQo7iKViuy4dDnOzck1FyzdENY2GNVEQleCWQwMtKgnmpSH7fkU9dqJG
         u+sRZokfgrD3I6LyIHnRBq0HxI20kjLcNE7Fes3nNAmbz7wX4s3DWTIsHpVfwR9k49tH
         v/QsJkolcKXezWwlWZ4MO6NtDevpUQyFRJ77+PGmVf72ojgqgcbZIHHVSmfHUPvj88zq
         7PUVtBbvmnbzNbZHNtahxqUEQCmiQtBMG4+IJOAoIuuYqag86MGm8fU79LAaazE7wIIB
         FcS7B5LKt/erohXKuTLqV6whl9pdFwcMQP28okSve6c5QFhqbDWMf40ygoPVXI3+S8dj
         k15A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3aQikGHSh2eJOiJJEWmwEj1RNZMojx71CpIbQ9P34qklRfwG8P
	7m6VEzcaqCFhF2k4oqN+OLM=
X-Google-Smtp-Source: AMsMyM5//pDpQE7vCWW0rbZBh+5b/rn8DXt8yoyw6MMFlcRGc8OmDVv/vN2JJFz5Jsc5GEc6lxFjSQ==
X-Received: by 2002:a17:90a:4607:b0:202:e22d:4892 with SMTP id w7-20020a17090a460700b00202e22d4892mr54482pjg.220.1664216594375;
        Mon, 26 Sep 2022 11:23:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a4f:0:b0:438:96ac:b3c1 with SMTP id q76-20020a632a4f000000b0043896acb3c1ls147218pgq.7.-pod-prod-gmail;
 Mon, 26 Sep 2022 11:23:12 -0700 (PDT)
X-Received: by 2002:a63:1e10:0:b0:439:3c93:25ab with SMTP id e16-20020a631e10000000b004393c9325abmr21244028pge.317.1664216592852;
        Mon, 26 Sep 2022 11:23:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664216592; cv=none;
        d=google.com; s=arc-20160816;
        b=XIlmWfSyaKT1xRyc+Rg8nL3Xr8qRryCLk1FVcR++fXV9R7CPapzSMajncgU774naf4
         KpgdR4BGssthgsHx6+ZxG+Mt1GHCNpmJngbfHYLDEa/oWwqHCMONZqWM8y28eREzrEKR
         sK1RQNHXk/Niwam8E8RIpVz+xDbTmmUqKhoM0AnCNLtA6MMbhpAKrVqvFz3iQG5dbCgT
         d/pOdc1/6teoOgx5B1YDmzThrPBHGfG7LJYqlUfqaZxfCQl24vDHx2MZUDOd4eFxScEj
         Cv0Z61x7J4O77Tfrs+/APbrB2HZ+3+Ng+zwZrKQo+4iSZsY3nuLrGw70ujBmSdajp8xN
         VOxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZbRJ8mO2p4vx8AyTjHr+MwJ8AVi8WB920WfIqpKjyQw=;
        b=X/TmpOb4A85KCG+UZs7ekDxXqNk1A4iZ5yO5UmHJDnTUlh8to+Og/fFSxxkkyhPrY9
         HdW17WILT+paEu/UonSBPWNY4q0snLlR6CgLfpiTHfTLq4nDs178FbgN3XmXGsnDrJRL
         URYnzkvPPOHuFwCKbmQQ5jYBo7Ps7Rnyf4tSyVtULSEJi+0WOf2le/coLUDm+QEJj9T3
         Uk6pvCWnzQZeDA4B3d1zCVv0LNlPppOkeLnyrHXNYc0HTYeaa2/LSx084s5wDonnfzQW
         Ei7jrDiYYsShcZhZPhBWhSekLLsG/btLxEsMjzird0wIuKOYjQ1wBo0DIKCNbNxrx6k+
         zgew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="F7JV5x/0";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id n11-20020a056a0007cb00b00537a63cf17dsi586508pfu.3.2022.09.26.11.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:23:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id b21so6996926plz.7
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 11:23:12 -0700 (PDT)
X-Received: by 2002:a17:902:bb98:b0:178:8e09:5675 with SMTP id m24-20020a170902bb9800b001788e095675mr23402986pls.91.1664216592557;
        Mon, 26 Sep 2022 11:23:12 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c37-20020a631c65000000b0043949b480a8sm10914556pgm.29.2022.09.26.11.23.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 11:23:11 -0700 (PDT)
Date: Mon, 26 Sep 2022 11:23:11 -0700
From: Kees Cook <keescook@chromium.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: Re: [PATCH mm v3] kasan: fix array-bounds warnings in tests
Message-ID: <202209261123.91B4E71B2F@keescook>
References: <e94399242d32e00bba6fd0d9ec4c897f188128e8.1664215688.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e94399242d32e00bba6fd0d9ec4c897f188128e8.1664215688.git.andreyknvl@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="F7JV5x/0";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630
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

On Mon, Sep 26, 2022 at 08:08:47PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> GCC's -Warray-bounds option detects out-of-bounds accesses to
> statically-sized allocations in krealloc out-of-bounds tests.
> 
> Use OPTIMIZER_HIDE_VAR to suppress the warning.
> 
> Also change kmalloc_memmove_invalid_size to use OPTIMIZER_HIDE_VAR
> instead of a volatile variable.
> 
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209261123.91B4E71B2F%40keescook.
