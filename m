Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSEAROAQMGQEG245TCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B7A315494
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 18:03:05 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id t25sf6436788oof.15
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 09:03:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612890184; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKlOwvJUn2sPRSQxFGDeHOgudzqA16ui5UgwIqxYvjakVr5YZzy4xI0VTtxKltqaA/
         bs3bs3cEyBD0ZK68DkOqz6UMG8vxMsO6XDPtMruXQDRqp0jW9eokVpJwUel/oDlXp50A
         ou68NiZ3J4SK1gp/uYWPkxbD6u/Urvfd6ryD89nqrQTQSrvhEAmPQbFlcJLrmsbKQ0+y
         xmzDsgdWTMc445Y8nM6aygW2PVLWWamkRucP9VLo6ltAnS9hQU8iqBWR73NlMCALfIOu
         mOuaV0Pl3AQjTHp4JikXd5Elv/OF4PtCAAKmlSjswy6F5GaV2b1zYp0NOVzr9dWHptCn
         fa/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Q6LMYdQc7Eb28VbnwpDPQ/gktpKXWUaF9JFaCv6eYpo=;
        b=T/M4X67BjuADDn+Wgd7Zn/wUO8ot63eeeTDzBPZk610q74zLqcHQkYZBoReys+HJwv
         Aofz2Ugy4RmnbT4xAlN47tyNXONlWXnJqtmvD0aFipI11nKWy14pqJdVv6TsEKhx/vIU
         p3APL+wgoRmIqgoJGXYh+2N2HUd2BHWha42tgjymylj4lEn9fA3s64A/db1iolV3ELQR
         YaWP6tbxuOOJKUiNijv+zCzTp58CuIooaE1476DeqQc9LYAKEH/kiEhhGxwYxog/zvjw
         u+jujj5aWsiWIcCZadgSNID8ZyzreKdI+DK6Oy1qeiuufTRiGZlofJNoZBmnBcP6iDXr
         25zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q6LMYdQc7Eb28VbnwpDPQ/gktpKXWUaF9JFaCv6eYpo=;
        b=nHXWEJxEa733bEpNQxpiAQR3gN2u8WE0CPxiFrvZL4fNw2+wKGqY88/SLQXdD7+Wve
         It+2JE5q5xuQqE4WRBAMiOaMqmk26Zk9X7MJL8+03iQOUlXJDkSKfwl2WLB33Ep79k7D
         5ZAu8lLLZqAZa10m3fnM/OCnLUta2ybZuWLKZUG3gFNyhW+6HP41RidhBqG8HmSefGY/
         H9z6Z1l8u/DXmDUkLhYdoY45CaIB3NQcElZ3gM1H17bZh75yz1TTitAjAzMwoQjNagQq
         0AFnOw64H3v3mZDVEe5bFfUS3ujrPzG024yPcjn1mY7MpF8e9UqvDDxk+c/Kou+e8ltT
         HNrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q6LMYdQc7Eb28VbnwpDPQ/gktpKXWUaF9JFaCv6eYpo=;
        b=jjEG7TwwTQ5dxkFuOs9FnCHsr+pJzD0grWMT5QXJSskuZmnTmvv/8h148bQlQMvCtm
         6QiYaKzCMusNWvYnp0SZliwT8zlvmFJ7NKzSSmOjkWM6dGdJ0QjlSXI4XLKtitX65PBc
         BivmYiaDlzOh7B+v3Irkv8pee2Wmw+UbFwVazf5+kuVqT2WErQ6BmF4E/tlx/CSp1l/Q
         A5Khmot3kONzDlPnjp51Qp9MRExBrgConFotPcF/jntrAozP7XCYqsFfvGam7FGgm2S0
         gxpY9tBZGyTJU3mG0fbAqoZEMXPc8TRiDV16g/TPNNSU3rPKOSKzI/TuA/Vub29+wwnT
         Eo1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tTobGMZBixkJe/Uu7qlEsTyAYATxSnF0pQ+9vSy0hmCBZiqhY
	em0QbAkFnSj2aCrnGK4edYw=
X-Google-Smtp-Source: ABdhPJyIon+cvAU7rzYEm9QhGkh0kTyun5Zw5nj2rI32C6i4qwZgppeMgxOsZSmLMaa/YaH/pGGtBw==
X-Received: by 2002:a05:6830:1bc9:: with SMTP id v9mr14027621ota.106.1612890184212;
        Tue, 09 Feb 2021 09:03:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3407:: with SMTP id v7ls5160039otb.9.gmail; Tue, 09 Feb
 2021 09:03:02 -0800 (PST)
X-Received: by 2002:a9d:42b:: with SMTP id 40mr16981070otc.248.1612890182775;
        Tue, 09 Feb 2021 09:03:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612890182; cv=none;
        d=google.com; s=arc-20160816;
        b=vkRSERVtzfc50LsDNEg9HxJu+EkpcdTe/RAalLcpxkIsbOjMyQ/6Z8OBf9Nr4N7hR0
         rnjUaaurZWxgl7xbS+XyB01ha2XQewQqAV56uOZVC8YAnOMKoRMRhct1Nrcwc2egFy00
         mNyx3TB6e1BY9zxEapaejJWaNbcDaQcZ6EaXvr64Rbm9DW/4CGlQsW/XL+vueDnO2wHN
         fIqIS6cwjOKcwQNl3ttJLFZu0cFh04xVDSSm7cCGV4/yk1tw3vCE/nVVoz2tWESgH2TD
         eQBeOEHAsNbJDgfcQ36qOUiZABNuiIo2pOE2WpxJHBnPRkTtSO0QnQ0teL3CU7nMMNAh
         xHXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=3OHs2b3LvpWcTTRDie+tW0Twcxcx9ffIVh/LimaFQdg=;
        b=F/uKdWZaJoEYsQ0AvIdIx9O+YICmuTZywQAORrZixXOBZ3ly7egjdZ+zcJwHGqLZ2b
         bjXm1W2oyJbGmrAjIh4YNE8gcGDGl39UcOuf7o1+Wsq4eI90hdN1BuQnKjEAoXh+soJN
         GuG0L0WfZmxv8+6dPeFGqMrFI7syy9uHDsbcdSP3Ad2/QRlWjlCm2LdU9PPeH/TDJ24V
         1ZwCGhs0Ka45thce6yGRkcUUzYlw7BBQ5n11ZZ/JnAOvcImLkS/Me6h4jxdgRd0eGJ1t
         cLGOOtFsZPwHpywfQ/xauNKu+LsBslGxtQtgVxaelInO3xGzQVFlePAcjTyK1mV1trdB
         61iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si595619oon.2.2021.02.09.09.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 09:03:02 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CAB0764E31;
	Tue,  9 Feb 2021 17:02:58 +0000 (UTC)
Date: Tue, 9 Feb 2021 17:02:56 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] arm64: kasan: fix MTE symbols exports
Message-ID: <20210209170255.GG1435@arm.com>
References: <dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
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

On Tue, Feb 09, 2021 at 04:32:30PM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index a66c2806fc4d..788ef0c3a25e 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -113,13 +113,17 @@ void mte_enable_kernel(void)
>  	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>  	isb();
>  }
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>  EXPORT_SYMBOL_GPL(mte_enable_kernel);
> +#endif
>  
>  void mte_set_report_once(bool state)
>  {
>  	WRITE_ONCE(report_fault_once, state);
>  }
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>  EXPORT_SYMBOL_GPL(mte_set_report_once);
> +#endif

Do we actually care about exporting them when KASAN_KUNIT_TEST=n? It
looks weird to have these #ifdefs in the arch code. Either the
arch-kasan API requires these symbols to be exported to modules or not.
I'm not keen on such kasan internals trickling down into the arch code.

If you don't want to export them in the KASAN_KUNIT_TEST=n case, add a
wrapper in the kasan built-in code (e.g. kasan_test_enable_tagging,
kasan_test_set_report_once) and conditionally compile them based on
KASAN_KUNIT_TEST.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209170255.GG1435%40arm.com.
