Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHNIS6AAMGQEBL5OA2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E63202FA8DF
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:31:58 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id n2sf13799262pgj.12
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:31:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994717; cv=pass;
        d=google.com; s=arc-20160816;
        b=TALk5vg4Buo4jgF6z9Dmzy6GnqNRD+aA/yDaZi71XMqycBLboO6SEfkxigybMxBYiV
         6Mw6MI1OMm0US+KznneOd9O6FvqjP3eZA6+Jn9PUU1nmKECSNaE0mSa9ntGsyzxVdDWG
         HwWfOfwp9QdfCfAeUq5CpzSyZJWf+6sVc5xe0L2+836UFQ1QZxz8A5IEV6lCN+pZbFWX
         McZMeDZzLMQay7Rg8KjGavCt7oIUbQDHb96NymSzaB3RoHSwrVNBFLntOluq9Ysc6ncN
         4JQmUwGDYYX8CN0nNugCHe6/Q1i0QLn9ITo54hjsc3JAD3XkrjB8xdw2E6S0+bsZSD6w
         zVEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iQEDVgkXuFOSpLuW30fESdia8oDbixQe2UWTvMCWNNE=;
        b=RjqXYL+lfrveSCyHdbBip6LiHRZGJT/MauZe3KjNEU1q4zVIRy++HJDjSkOr0Pxukt
         Nnq9AG8mkGNRiJmowzdTJ0BX1n7UYru/YfS1U05N2+WSNmOQVgD073YROoSZP40Q1VwU
         zzs1Dw1efowqfafjF1jTMawAtLtI1+Elibi18/DdYgp4wI9Wkm10o8+MtQnuOw+xtI9z
         51Qn39QW1Q33mGio+pSu6UUkhHrXzW6NWtuChuvyrl2PliQ1eBwdhIMxU3OnsQEGR3ZB
         QflRUbIkhHsG3mQOq7ACpnOQ1gQ6Cgxd+0DLCCtMnOJUOychsX7jD8DsUplRjUDJZQOT
         VQFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQEDVgkXuFOSpLuW30fESdia8oDbixQe2UWTvMCWNNE=;
        b=eKR34pPyKQBYLgyJ0F7ghYuyAnZSVGc8q9MfU8aSZu7SLVFk3t8kOdF+4B2vW35Z1y
         7MW9hkFplfbFgieN5WWNCnNY7d+4qrIP4h3wKACWDBNgaVjX3rkiCA58hzW9CzzhaT53
         wwT09IUhoHYTE7WC1n2skYflrhAgpxySXr3I7snscjF/DK35JDR1kG6sLFfD64ZvjZFS
         kB1QY0RJX9hLfiT1NG0I1naGxrMJO6Ame3tWws+ybTdqS8xH2BgPqxnIiyVkHg+Y9bqC
         HZgoB+QgpXtDOKvaw1KdGK+8kmHsaiS+/7YewCcRep8jEGtCdSdoWyE/hGsIxAB9dhha
         dd/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQEDVgkXuFOSpLuW30fESdia8oDbixQe2UWTvMCWNNE=;
        b=t/b55edwB/59+64/56TVxjXLMi8HMOF+VUAKQFWCgqogp46a47HaEIfBRWqfx+bnJS
         SnvONpieJBXQcSkby9YcJe42p/KCwHou3pHJMVw9XCr1/3jBzq2s+JP00JI2jAFUjxoL
         c5l6p23oSrj88iaGVky+Hbhke36ERX0dZu8RZcN0SBRH52/fmxsFVehGKjwVIkTyuGoD
         nTB4TCDOd6ZUgyIaSFgQp0Q6r0prCnZY7TA7jZPzOIlCT9/5OiMwoAeocOZRmoEXr+S+
         O43lG1hWa1473i9MAXwOX8qQN2Bcew3BXmovLa1XrweUhS+uxe6gV9bCcdrkC0jLeKPg
         20rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ClAtaCyZqt7E9yyo6Sz9HeXPPNhJ1aSnwltWmoV32ZzsIUazy
	N1fBE7VqjXuWoIpsH8bZXwU=
X-Google-Smtp-Source: ABdhPJyXKnNwcJEXGJDY24rJcEoryckTyhP1ZR/eV/KXQCjUJSWvmCcBVJ/iXssgiGTxZ5OmXmqQDg==
X-Received: by 2002:a65:688a:: with SMTP id e10mr876888pgt.347.1610994717635;
        Mon, 18 Jan 2021 10:31:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac0b:: with SMTP id o11ls9603196pjq.3.gmail; Mon, 18
 Jan 2021 10:31:57 -0800 (PST)
X-Received: by 2002:a17:90a:7e88:: with SMTP id j8mr593448pjl.217.1610994716985;
        Mon, 18 Jan 2021 10:31:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994716; cv=none;
        d=google.com; s=arc-20160816;
        b=UeQ2otHe6rI8INd1hfyd7v+A9VZa/PeeEvsVklULMEAKghlAgF6EN2bCEeZMxSVU8Y
         CKWB2X9GNcGKpzCVd0kWBL+HJ8Z3UkSj9CvW35BTMCO/2sSaJP0Vo2CZM2s2vIxul+6X
         WzGZEPUHbMJBGnshElQAzFatdtcwJzCQq3r+67hcGfzh5GqBwlP1F0eXHrsIbjCUz3/K
         9LSpwf214yYj0jaE6bXkgOAuBPUYMIS/Jfq5p+7LpZClIkfxPrXQJAv/n9K/+3CDM+dM
         Qikq3ExI/Gag+rItp2fFV6RMHG1h3nyUsU22IJfu/Iy1yWFhBaX7t4DQ/FH85AlUN9Ag
         LU/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=X74unuTdMFhbpe9pX/T0uixE/VxGnHhxn2j1GHy5oVk=;
        b=hyFcHyvaqiqzQc3GknIwNydQpPY2ewzeB3Z2BfZNpW8uj0kc0+9qPDnUqnFQAVBOjd
         seuqGF1RupXpDeQ5QOdmjE7h1EiGcNfUcGgFVLRBk5wV1sGF7CHmMQ65uP7WRPrFzIcC
         i3J7xcC8/ij7EGmrpdIu0BvK7R2WjTaV7mZN8NLXJSHz68uHxgh4s1vQdfoIf8RsNXI6
         WWxFOcDEXbKEVTiHbSDCKd1GjEDFmIYLKkYSq24EBqqtPLg7jU3xPi7GsycptBnyQ//h
         iH50SClNkM2KaYkpBTeUVcTjIMI4Ir/UrbJnk7etC/ribIgP/T5TdMMlIaC5oPr1Gw8I
         KLsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z2si11148pjq.0.2021.01.18.10.31.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Jan 2021 10:31:56 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DBFEA22CA1;
	Mon, 18 Jan 2021 18:31:53 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>,
	linux-kernel@vger.kernel.org,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	Peter Collingbourne <pcc@google.com>,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 0/2] kasan: fixes for 5.11-rc
Date: Mon, 18 Jan 2021 18:31:52 +0000
Message-Id: <161099467077.3190.11574628584185482983.b4-ty@arm.com>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <cover.1610731872.git.andreyknvl@google.com>
References: <cover.1610731872.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, 15 Jan 2021 18:41:51 +0100, Andrey Konovalov wrote:
> Changes v2->v3:
> - Fix up kernel pointer tag in do_tag_check_fault() instead of
>   report_tag_fault().
> 
> Andrey Konovalov (2):
>   kasan, mm: fix conflicts with init_on_alloc/free
>   kasan, arm64: fix pointer tags in KASAN reports
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[2/2] kasan, arm64: fix pointer tags in KASAN reports
      https://git.kernel.org/arm64/c/3ed86b9a7140

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161099467077.3190.11574628584185482983.b4-ty%40arm.com.
