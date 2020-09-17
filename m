Return-Path: <kasan-dev+bncBDDL3KWR4EBRBV5OR35QKGQEUALHZOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B1A6F26E1B3
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:05:28 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id f12sf1687182plj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:05:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362327; cv=pass;
        d=google.com; s=arc-20160816;
        b=x5lQktmM4f10uL7FvUsKl6RZ4/gtCME3b7acd9Legr9fxih4iFNCQf9nJQ6vhIFUkw
         gJEwKe1GIYOjSrIhlECKs5tGRMhUOy6m7aNcnphS+Z+Gqr07CkZDklXhcIo1KPfBGO0i
         gOPjyiSxOUcw1zbz96IEATsO+egC90tIjdk1ycC+larjv4EkIbplfWAbNthiMpcrnYsz
         gfyBvqBBs2yY69UTddrSSrIXV9RmnAUHDYJ01uTFC8wVEofQUZRnihsQSdnJSnM9RgvN
         tHsyVaYuH/x/ITv8G/5wutlipqt00ySBR+C7SHBVeb8S1+4XwKnQyRcZ5oHzQydXwJfx
         1kcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pPkXqf2WdlSIHFO46LZIKkGDE6VIBNrHMFG1Lq8lhUw=;
        b=Lk39de5bEpnFbbsgMGoY3mVAnmPcbYvDUtORh0KLULWummiqMfccVGfkNkhZiO2KE1
         ZiVXkVpF5+KQO3SBPWuAIAffnBEpyjkUn9V4Z2ipriDaIwYxon4P6+v0UVilDUGEOot+
         ZOtnewMKntf+ndR2pMJ0EIGR9/DiP+aSxuq8n8tocULxb230/MgIdUZK/SPJM0mhTtG1
         8TYisoCm5ApZDfUlu3OxI5qA8xPixMR8vDrv/iHnC/NayDUCgcRr8bkz/FACT6kNoaDp
         /Bn9EBNMsS99PGbtLRA2I7yzDc7E5E2P51NRwGsifsxzUl825Nc9sUIgSk3zbvZcIbhR
         nefA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pPkXqf2WdlSIHFO46LZIKkGDE6VIBNrHMFG1Lq8lhUw=;
        b=IPq/kOVwWOk4f9XKNhI0OBJsodoHcxXY0WmsBowUoHXckvNr4dfNiiKSS/DoqAwrmB
         gO3WRe+fxmHGmnRMnesyq8d/rC8fZbwHEWyAq5U7Hl0NG2ozO+TWBJ3LVMYJ1ahuVTlL
         bRZIL1kq34KlIvXUdc7gfuW5Spto7E4zosl6yExHQ5VvjI/anauv0K7jSirzeaqU3zS7
         qNehEKrx/e2JImZ32BJNRUUjGef0rwKcs3nQdZKV+/8acaodJlhlMnzF2oY9uz2t+hi7
         JjZm7m2tENgpY1e1tycIZ3qEL2URxbzgDtlw6dqjDsd0YpQcyT6lF5PWuBNAief3db7H
         Hozw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pPkXqf2WdlSIHFO46LZIKkGDE6VIBNrHMFG1Lq8lhUw=;
        b=eCjd2vWRnbQ6sGiAc5RLpsz9hYhDn34AGklYM2qwchz0VKXdmye6Jw0ofqPPJ8brzV
         X+56iX8VMeb3oh/j2a4qejFhg2KWtvOWn0yu9+O+VO4jgGh2eIgCllVpI8FQqoC5jP7v
         6cOR5J0QsXwqPGD75d/7Kr2dP/38PQuF2U7fEaAdfTXkc9sIYSAvGH+pM4afic7EWKo+
         S38/3uIYgGObfQ7eIrK4QmtjXDLyhytN4/BwSJshzGD81PkeZwc4BKz40mTW8WrsFQJH
         rbEICPQ5DxOsr7gdnQ9L+mxQK6M3Q1apvNmYi9uGLCfhLUHHP8Xqkv6FhCIPy+bkcUae
         f4vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DpvZXrB4qJlK+sxz26P9pNxKfLYMRZvwSUhM7+o4AcsofwlOf
	GGV7SPs4GWzf8tR3TRDg/xM=
X-Google-Smtp-Source: ABdhPJwXya0YTW03Jla3aIPlilvJWlCRctjFuFaYLNfJpeKeeXD+9EHTPnOA0ufDHJwGnS18oNyLDA==
X-Received: by 2002:a65:60d0:: with SMTP id r16mr17410869pgv.348.1600362327438;
        Thu, 17 Sep 2020 10:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1362250plr.1.gmail; Thu, 17
 Sep 2020 10:05:26 -0700 (PDT)
X-Received: by 2002:a17:90a:65ca:: with SMTP id i10mr9482700pjs.137.1600362326835;
        Thu, 17 Sep 2020 10:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362326; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2Sp2Joazmte6aFCAHOO1Hk87Dk7PJligNoWmc+MqbtPPoc9BMUChV3LHO9uMHJz+S
         7lbrvK+igh55wJaiwS6JEWuvAwTnn5UthXf77M1lXxy8295BkBB7IQ7Sk3UHJd/5k1rx
         rHIqAV2ganuhlztnP8M08k5EPuHEPcoTsnPVQbWHmoXeVm7es7a7HMhD5E+1qXZ7GaMW
         n2EAYKpSDaSvrCGECwcRP72meNjdElNAebkkJwnSqQch7CB8FzBK1ftguR0b97YThnbv
         yghNQXrv4vDmkgA1CTrK6GL85nWkrf+iRNuPD65W/AbSjiaASFdwoDM5IsDrEZtiJRDf
         0IAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=NApgIKload6cdAOcnW6hqpxAMCUKQsB/rseQmLadBC0=;
        b=mQVexV9Z2bD2mHFie/2Zef56lnRjv1YJrwfVbhh8SPw5++t1kgI7A8UJk2JqYw2Hft
         5dEoe5TDgluQW3ANN0C7BIggnwrjSpxuLHdPVijSNHlW7RMZYe2WtSQC7YGWgj4vE6BQ
         4mxyD0vTOu0OtIo7iFFkY7q5P8JgZyByzyPEPaqTGOd8dISGHTtm3hXqT4zbuz7llkOR
         s599tb72PEYg76zh6XGK5cUbT1ZYqp764CvakrDm+iMRs86t45hyW1FSzRQua5dUdvTK
         S18G4KoGLRYreF5iIYa8rcbfek+jFCQEXq5B7ltW6YRJA425zKqrgbxWFxcvz7+zzCj4
         9tQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w136si66041pff.3.2020.09.17.10.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CB5C7206CA;
	Thu, 17 Sep 2020 17:05:23 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:05:21 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 19/37] kasan: don't allow SW_TAGS with ARM64_MTE
Message-ID: <20200917170521.GM10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <42f25c11d97aa8497ee3851ee3531b379d6a922e.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <42f25c11d97aa8497ee3851ee3531b379d6a922e.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:01PM +0200, Andrey Konovalov wrote:
> Software tag-based KASAN provides its own tag checking machinery that
> can conflict with MTE. Don't allow enabling software tag-based KASAN
> when MTE is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170521.GM10662%40gaia.
