Return-Path: <kasan-dev+bncBAABB7EUR72AKGQEVX6EHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 9792F19A21F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 00:55:57 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id z16sf19425970qkg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 15:55:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585695356; cv=pass;
        d=google.com; s=arc-20160816;
        b=AP+E9xXWrXZRVNPotaAHRxRbSCIvDQlM5x56w0zWWnObNBm7bVLeYdl0PtggZna5Ty
         DMGqnRQfbk6DcdxSs1zwoY3++DDMAcew7WpI2Wy7uh3Fd/WYqydkFpgKgH2E8jZCxyNU
         ZOwgoZaUBAh6skeeX+Fl9WuISUBX8H2YW8uMsABh3xHmh5J2lNc0+47yiimTe/VPrzgt
         IZ44YbvOiCEGdSxnjMqjZeFaobZh+AK1x1EZpdyNvxMgDJpiDY/0Bj0Raejx3bvSv7PE
         YrLJgxYnZRMqmLROhcHAqbCZSb7HpNtxdLsy320jnb3oObGjkrJzNn6bYBxRd9rKI8Xp
         zlyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=qm8vbrfyQeLK+f/lRtpsHCZKqsRpo3/7OtjWgQuy1EI=;
        b=Qi6yEKAQQxPXp476WAwnf5vhhBKjbTQ/xtUvCStiVNYWM9boKxYM6Uz8R/FG4qlnNs
         jWTmuGXPVy/4WJkHx8QC2lyJeXSbzxr3qcxseU/d0+XlS/rQNUyOqDx8EmWcO3gCtlFe
         HMB3Q/zqHrXfcr44Mrw/6f3+2gK9P0GAXnQoXHZHbHcphNS5wO+ErNuuVh1I2s7OsSC0
         +70tc1Y3MkezPE6HQTSb1NeUJKM+4KlK+vRnMOHHN3Yck9xaHfQjyqS35NV0w1p88gMO
         bRypcAPvU6TaemuoJsmO9Yr6yGS2UldCp4d9syYlC9CrXr8SEU/AhFxPSov6WszHCS/L
         8aLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="mphGjb/g";
       spf=pass (google.com: domain of srs0=zaht=5q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zaHT=5Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qm8vbrfyQeLK+f/lRtpsHCZKqsRpo3/7OtjWgQuy1EI=;
        b=l4hoQqIdXILLRsyORwCOM28DQr39osPAj03bJ0OuioIQfybXIDQFu32GbAjZUg/Gno
         cKUbbC5U9iHk1vDAprFoynFS7go/pswGmfvx4sEAEu0orXPEF62ciALIR7BzjbZzLOBa
         29iKXW76koVacpXLMhfiPAFWyKY7loZ/rMf4Ysa/bKeY4hzQpd7ssBPbuHnzv3nZUtMW
         Zac9WuKWG4qBfRUR2RscA/71jbIZ88h2AKG17abWTp60SvDfvRi5C7ss1+e1N63wkfC+
         nRkqfu4uPbo5+biV4MIrl0eNhRlpkzHBsk0E2RDgq0LkauXGV3AqsYaJcHi4uPufa1Oe
         mppg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qm8vbrfyQeLK+f/lRtpsHCZKqsRpo3/7OtjWgQuy1EI=;
        b=oiz65VjrwilRzUImLSGuLTrjdjhmyI2jMgNT37PYrkDi/YmYFAkPCAESlEEorXxBid
         GxKugqmZ9adq3sBSIf3phy43Lh8o2qqA3eFVJSl/lQuSL8ddvcDTgZMDJd5CKzmx6aV1
         w3GI7/UNCrFL5vf371wvmpfQpRskdECxAcosWkdF9EIZU0eJvpKi8rddc7lffJnw1Qhh
         L7NLFyRWuy5p1x9WU+JDeRr4rIYZ3j6OlMi+6ybPz0Hl+muBSewj+og0iiq6szdSIa8k
         Nk1qEXAY+/ivZ7tIdTSxC0tpWFn3TYEnal36QNTwKRLk6mOmoSeGI+fxGflVCvyvmO6d
         QU2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3p9bhnbFvHCs0bBxwqCpsi7TGaN+s1UeU7I+46Ou60yWNZNKK5
	9HVvzuNmGJ3TIbBLidcxQmI=
X-Google-Smtp-Source: ADFU+vssuvwbbwGjmAGlTLArwwCAn9LLQ1R1/Ap0od11JsbyUfWyQxJwuQRSyFRtpBuGjOaUR3t9Bg==
X-Received: by 2002:ac8:5291:: with SMTP id s17mr7527860qtn.156.1585695356652;
        Tue, 31 Mar 2020 15:55:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d49:: with SMTP id s9ls5995101qvb.10.gmail; Tue, 31 Mar
 2020 15:55:56 -0700 (PDT)
X-Received: by 2002:a0c:be08:: with SMTP id k8mr19241397qvg.62.1585695356358;
        Tue, 31 Mar 2020 15:55:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585695356; cv=none;
        d=google.com; s=arc-20160816;
        b=XZYwaAjx5qn+KaaeIYcPJiVR6DmQtgQljmmIstgUTjknJ6hjGIL3cXDsKWXBh+YhXM
         i9NLdBQYmriFjfW6ZSOoWSmJw/ULIN0tacuOGL0SrX+WC72gDTXfHl8vqCL0jl4iIOyC
         8E+a7VTA+3dYdi1xIms4j/aOvw0uhHFkDAzrJ98B2ibVzBX2n03YAoIoUpuQJ+4+NpgE
         Pcgdx9FmnQyX7mtG0/zvNRelY5Wpu7OUkwQK3U4cQTsDFAYrdxct2V5Ux6/oLeSkOauV
         AXOiqgvyj/4HjEURSCUvSpsa6giUzJwkmzhy5+PTRYnQ6F8nNYEBsTH3f8wYDIfnSRAf
         wCDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=lYg8gNXt5ClnOyxIU7EsBTAYczICzaib9zDIlyXepu4=;
        b=hlRweFNtkUA+qc78OBsVBPQYLRXNAuoabKpSkehEg7/ZMoOaqrc/fvCr5VaUPvMYc1
         YieltfsBc+KIMpeETxhI8XOcUQE6yB3EP/axuTHwL1qzp4vLIJd7j4qeHvwCxT1w3g2A
         Tjp2XPd1xo4ahdxD0HdqWKzO/8rP1wlGla9Tsuh6uwE6gu5B4QKL3UtH+vOp71FTS76B
         dfQObJrYIOp+sJ2Yr6VFt6rnIlf46zY1e+XreEr1XrkGAA31Mqboz6TfhHwRgOEbzF82
         7Kt5mQ2zlhl7ovlkmmvBGcpVP0pSUnqngOWwhqYCSO3aQRziKsHqmBq4K8Mqn1yPUuyL
         eV3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="mphGjb/g";
       spf=pass (google.com: domain of srs0=zaht=5q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zaHT=5Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x11si14051qka.4.2020.03.31.15.55.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Mar 2020 15:55:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zaht=5q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2DA78206DB;
	Tue, 31 Mar 2020 22:55:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 05B7A352279F; Tue, 31 Mar 2020 15:55:55 -0700 (PDT)
Date: Tue, 31 Mar 2020 15:55:55 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Move kcsan_{disable,enable}_current() to
 kcsan-checks.h
Message-ID: <20200331225554.GA28283@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200331193233.15180-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200331193233.15180-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="mphGjb/g";       spf=pass
 (google.com: domain of srs0=zaht=5q=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zaHT=5Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Mar 31, 2020 at 09:32:32PM +0200, Marco Elver wrote:
> Both affect access checks, and should therefore be in kcsan-checks.h.
> This is in preparation to use these in compiler.h.
> 
> Signed-off-by: Marco Elver <elver@google.com>

The two of these do indeed make data_race() act more like one would
expect, thank you!  I have queued them for further testing and review.

							Thanx, Paul

> ---
>  include/linux/kcsan-checks.h | 16 ++++++++++++++++
>  include/linux/kcsan.h        | 16 ----------------
>  2 files changed, 16 insertions(+), 16 deletions(-)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 101df7f46d89..ef95ddc49182 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -36,6 +36,20 @@
>   */
>  void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
>  
> +/**
> + * kcsan_disable_current - disable KCSAN for the current context
> + *
> + * Supports nesting.
> + */
> +void kcsan_disable_current(void);
> +
> +/**
> + * kcsan_enable_current - re-enable KCSAN for the current context
> + *
> + * Supports nesting.
> + */
> +void kcsan_enable_current(void);
> +
>  /**
>   * kcsan_nestable_atomic_begin - begin nestable atomic region
>   *
> @@ -133,6 +147,8 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
>  static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
>  					int type) { }
>  
> +static inline void kcsan_disable_current(void)		{ }
> +static inline void kcsan_enable_current(void)		{ }
>  static inline void kcsan_nestable_atomic_begin(void)	{ }
>  static inline void kcsan_nestable_atomic_end(void)	{ }
>  static inline void kcsan_flat_atomic_begin(void)	{ }
> diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> index 17ae59e4b685..53340d8789f9 100644
> --- a/include/linux/kcsan.h
> +++ b/include/linux/kcsan.h
> @@ -50,25 +50,9 @@ struct kcsan_ctx {
>   */
>  void kcsan_init(void);
>  
> -/**
> - * kcsan_disable_current - disable KCSAN for the current context
> - *
> - * Supports nesting.
> - */
> -void kcsan_disable_current(void);
> -
> -/**
> - * kcsan_enable_current - re-enable KCSAN for the current context
> - *
> - * Supports nesting.
> - */
> -void kcsan_enable_current(void);
> -
>  #else /* CONFIG_KCSAN */
>  
>  static inline void kcsan_init(void)			{ }
> -static inline void kcsan_disable_current(void)		{ }
> -static inline void kcsan_enable_current(void)		{ }
>  
>  #endif /* CONFIG_KCSAN */
>  
> -- 
> 2.26.0.rc2.310.g2932bb562d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200331225554.GA28283%40paulmck-ThinkPad-P72.
