Return-Path: <kasan-dev+bncBDXYDPH3S4OBBG6TUKVQMGQEADNA3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id BA0EA7FF38D
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 16:26:21 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c9ce8fa88esf7610541fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 07:26:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701357981; cv=pass;
        d=google.com; s=arc-20160816;
        b=bxLw4bM5EuPMOKDmMHkY7bMA2mamyo6/+NNORKc85eqXRjHFDWEhm1689Pb+O5Hroo
         yFaTHc6ZnyrRHlx+FtCOxxoe0vIzusY5v7kcgS+cmnqXZ/KbkdZw0d+beN8H6tmc24B/
         yLG9X+oCdoJKuu8cNfD/bmgwqWm68ox3o4hMOsJodCz3vZI1wqbAW7JQvnGEIg7aOVoj
         XenrqPmpMe5FxJet22mOBjqXxfH9nWoDz/9RKKVheKITic8+ZVo7V15SiDTCmVO7z1kc
         9foi7YS57zqqMYidezRKsm+CCCE8ibPDhW5+WVLYfk96bxQcf6GU90q+WEplBr3rwSO3
         /X4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=C0RLoOAIqIQ5yzUl3OKFh4LnSuBKdPmSPRoONbzbvY8=;
        fh=gtwm6qN9lskLrXqGcgQSmKN+lN7yfNQhDGa14RKei7M=;
        b=wab1p/IrEkvBSeNlq1fzPZeNJw0ou6YcdHb2+IBXN21QJdwsa6zEyJvsJajq/GVnTa
         um37bwMYJacK/PPgLmwwMpXFRP9OUFrRWA5hVkXKJOAuPJyhghCHrgK5K/5OfiBkDONd
         eFQjgpz309k0i2E6SYuxyqR1paVBfpKUbmJD3CaW9nAcuJPiHzO0iXVDpDP/Y4Rgy501
         9p5TDuy4qWGWFXLpQkoE8RVVOKuGyc+gdQE9CcHV5xT+k5lGcl01grf4SMtOK40u1TnB
         MtjTesoNflc5eqW1yRCb6M61D3kZZspViAo7WSsuMK6LIORxf1kURcvyDbRfD0R6jkRn
         V8yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701357981; x=1701962781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C0RLoOAIqIQ5yzUl3OKFh4LnSuBKdPmSPRoONbzbvY8=;
        b=iLUw23iFKJBUuIGw4HRYqmmXyoaRh3eawXlQkOzLcQG+NgV/ZDlT+EBFNlsO7MuJFF
         +TVEipl1KuS4702dkRRAT007HB1NlfaZTvKoeCqo6o95G0OC5xyU7sYJUv4/GBb8tK9D
         MlAqyTefWRQVeXF8D2YGqVzTLz9bIf4CI3K00fyWeo/qa1aInR3VEmk0rw6lfdFbwnPT
         67RnzqHWh4aTt6tLl2G4BnoCoim+rBBa9R9j35Pfxc0ibHt68VmeM1tBlaZNYTvm000e
         l6BYtqoEYpSCmpfWXTQuH9ECT4FMCI76ZQbkSyE3w0hrPlqBoBHZ3RTupHQTKYl6tLYE
         tLfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701357981; x=1701962781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C0RLoOAIqIQ5yzUl3OKFh4LnSuBKdPmSPRoONbzbvY8=;
        b=SrM49y0rCaTBoaBs5PoDwODUEbmH2HsPwUMqhie2TYINxVmsEGhPYFcVJZ21oyrg0u
         9l2AbkXihCouj4VGuSgxL//+emL6D+s/giNxVwyMG/LOTNqkPwOQHefaG2epvklFM+Mz
         t5zGS6xuKrg5YnaHHx4E5UR1Q3wUXGE4g2GsR+cy9BvlMhXLTwhtSdy9hsOFeKDlxUEa
         LzAK4Eb5L2Yp9ZmcLDpCKMgpHUo0Xxkfw677tm+fAGejCCsiwwZL2cG9M+bzWG8ftCmk
         vE+/1050G4Ia4J4y/5lBB/Cy+TJBQ5FUKFIvkVOGt3QuXxmJ/MpNO6LlFyO8IXN71lfM
         c7Ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxIe9IHEScQTbE4p5hg4QUmFq3uh0n8+wajJt7mL7NJG3dJ1yV2
	Ap+a5VLkS/J5qK4Yka0S9js=
X-Google-Smtp-Source: AGHT+IGB6Zkb3qVUcypnnF+VH02tSwz/wQWbfwxCANrUgH57LQ2c5Sw/yodjFjfIAueYsp2XsoltHw==
X-Received: by 2002:a2e:9ada:0:b0:2c9:d40e:610f with SMTP id p26-20020a2e9ada000000b002c9d40e610fmr854580ljj.50.1701357979981;
        Thu, 30 Nov 2023 07:26:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6688:0:b0:332:ffc0:4860 with SMTP id l8-20020a5d6688000000b00332ffc04860ls422717wru.1.-pod-prod-05-eu;
 Thu, 30 Nov 2023 07:26:18 -0800 (PST)
X-Received: by 2002:a5d:5708:0:b0:332:ea44:8989 with SMTP id a8-20020a5d5708000000b00332ea448989mr15705785wrv.30.1701357977817;
        Thu, 30 Nov 2023 07:26:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701357977; cv=none;
        d=google.com; s=arc-20160816;
        b=NDgZJzV7pDP9hV0LrX5G/ndfDOXbrdMQtvkQyDQH1OkZRfTFzLVjI2IPd+Tjodevs3
         aom7HGWt9Wff04LINPrKHkKTv4yN54Biocbhioq2Jw+J16tiXnQYmxVBMHuYAVazsCFY
         QQCxYhCWYX4l5WJV3aNc8tJ/QL/IrtVF3myuK9E69lsGRe1MnnydBD8VE1ccgY06r3GH
         7zosuX4ndOEolQEO2B5Sy6AHFejNvii+2FU3t1tp0pQ2Eq4u/gUu3t/9icu9ZdTZM8mI
         O6inqrDMre8+qX49maE5VJUOWNlyROMUESfrgGfiso3x8Qe/Chp0SNzQgAJ6K7tLprwv
         VPQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=mxIiLrFJ3h2AITHNfurmssPmbrlUNKlJzFiV3X9eiys=;
        fh=gtwm6qN9lskLrXqGcgQSmKN+lN7yfNQhDGa14RKei7M=;
        b=VMc7bjsjQXikhIKiieQqBDoehOyshvqnLyL9dlNQNkFMGs6HXIEotMONniWHZUNOG0
         ueglVc6k1j5T5eS5R3xBUhp7A994SVGFk3gG7dbFPhNno1dmPR0JpLIFCRw/VKhI82HB
         FLddW8JhwnW8HkV+XpZzNLwaD+bO3QFiSlKcoZEl8CYvLtTpmMwW4vbrQcNpVXqupRjr
         QZMkFlg7uTiJzoT8m2kslARB01cqARXVKShvjb8ZHJa2UW1J6mj5FTVUwjVvswPJ/Rb4
         xCL9gdZBkGRJO4B9Jguo/RG+RkB5zUb4roNCeg5sADfDHXqg0QOtec1SwUPLYoNxjz+U
         XF2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id f10-20020adfe90a000000b00332eb1f35besi90973wrm.7.2023.11.30.07.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Nov 2023 07:26:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2F54721B21;
	Thu, 30 Nov 2023 15:26:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F24E713AB1;
	Thu, 30 Nov 2023 15:26:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cXTBOpapaGXbYQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 30 Nov 2023 15:26:14 +0000
Message-ID: <414847ea-b7e7-aa05-5e2d-de50788d9b4d@suse.cz>
Date: Thu, 30 Nov 2023 16:26:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH v2 16/33] mm: slub: Let KMSAN access metadata
Content-Language: en-US
To: Ilya Leoshkevich <iii@linux.ibm.com>,
 Alexander Gordeev <agordeev@linux.ibm.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
 Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>,
 Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-s390@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Sven Schnelle <svens@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
 <20231121220155.1217090-17-iii@linux.ibm.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20231121220155.1217090-17-iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Bar: ++++++++++++
X-Spam-Score: 12.69
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: 2F54721B21
X-Spam-Flag: NO
X-Spam-Level: ************
X-Spamd-Result: default: False [12.69 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[20.85%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_SPAM_LONG(3.50)[1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.ibm.com,google.com,gmail.com,googlegroups.com,vger.kernel.org,kvack.org,arm.com,linux.dev];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/21/23 23:01, Ilya Leoshkevich wrote:
> Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
> KMSAN to complain about touching redzones in kfree().
> 
> Fix by extending the existing KASAN-related metadata_access_enable()
> and metadata_access_disable() functions to KMSAN.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slub.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 169e5f645ea8..6e61c27951a4 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -700,10 +700,12 @@ static int disable_higher_order_debug;
>  static inline void metadata_access_enable(void)
>  {
>  	kasan_disable_current();
> +	kmsan_disable_current();
>  }
>  
>  static inline void metadata_access_disable(void)
>  {
> +	kmsan_enable_current();
>  	kasan_enable_current();
>  }
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/414847ea-b7e7-aa05-5e2d-de50788d9b4d%40suse.cz.
