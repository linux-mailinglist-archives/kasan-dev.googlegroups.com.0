Return-Path: <kasan-dev+bncBCO3JTUR7UBRBPVR2SWAMGQEGVBCV5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1913982296C
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:20:16 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2ccdd4dc5b3sf39628201fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:20:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704270015; cv=pass;
        d=google.com; s=arc-20160816;
        b=CMjZLPUp2RZLIdakHph2dQo4LIm+cQ58aS+nhefn4KoxdiQVzo5yKeeyJTFFQyIiZT
         HL1SpqDANAMeMk3jxyGQZ1nZyfaTC+1OY/nbXHxSHtaJR58vqTR9JRARu9Rl4mNxrb3I
         zoBGNXpjZ72OriqE8JToq/D5BLtot2514JqN2u8N7xJTMBlNCunJaZRO5TTQvbdlngEy
         hL3OKBpTql5GfGOp32imqmBKYRihfbV+xqA/aJzLogw9td9IR9HYIg4mpfYoDKSeQu8W
         c9gCrKgb/lzktntTbqJSDhQf4G1e8CC1T7zqF/77KNks0Lp9TvJecS4d5p6r88ldayni
         6ajg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=o4sk+G2j8UZUv0NqE3vzNlMjC5gASfA7FKlcttYthyc=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=iv2v/I0bJvzoBLupqYlZvrMunjnZ8oSNQYT83PDXjFN65Ernqh+LFkJtPbiuUfZwU5
         g9h6c5bwkhB7FRxw7zAOoI6X3ze1rNZcOabynGDctb0yYQh1gYrViA9bU3gPhBw23h2d
         JBbmraDjd52JWvHPXBYLd2CR4kQgan0bfyaOmWCPDYofgMBXLZZPsxJXmEdnHKebqw7J
         JSF1g/wmm8Pv4815STPCoFV+z62uM8XmLeYavI8PbOnCK+QrrAHSkjIeQKT5rpJt1ZNj
         InDO5/N5XSCoA8BpGWqTrscogm5/appi57dZ1ilUSQ5mvmmlKXtd2mu37UBN50lthz3x
         3jzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704270015; x=1704874815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o4sk+G2j8UZUv0NqE3vzNlMjC5gASfA7FKlcttYthyc=;
        b=rPyW/eUtXervylI3pwWhIea/m8nKLr6sYNO2+wDcfLP1K+FMLSP46hlqRuKlLw6qAu
         9EzCt4DV7shH7nx2S2y4INjpnx/LCNLPU54ZpYTvqv+w1waEZtaYV+ulF1M3JP1yTio7
         QOV8XxqPTV31PUOVHF61m8z42njmWCPGCRWGjo+fJ7I2wRnnV/4mqS+z/iBpgcD+mcKJ
         cJZ5/eXs45GKOnlm+S1Hq14O4VVpOSBBJoLzvO2T1SEwIDWgWz+e2CKXpglDjPcFgQtu
         EnRSFtAK9Cg2MCnNgrAYdZaXUCIrV02jcdSg5+Sd9ghFXjZp1pmLn7/Y7k6GITYwidWw
         PzQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704270015; x=1704874815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o4sk+G2j8UZUv0NqE3vzNlMjC5gASfA7FKlcttYthyc=;
        b=Pj7hGwlnEa9arNh1YQjxZcMepAb1ZCQtTf/Zmosw6t85PaSKjygCv1ySRvXIhjyw62
         mMjWclMs2Gdo4MzTUbQ3jMtAVxX63EYTm3M0ThO0+945yPbAAbuAC6y6wawsWBM1V1pV
         9Pmn6Q5u4+K8q54E+Yhn78T/LDxobtbHkXmvAAGdguzV+dVuVbytBi0bXAZvi5dXLwRt
         TAAmjXgbebd1wa2cGF33gfem+A7Vkl/Ark/RzRFXl3K+LtoN9lD9+xtc51pX8bpucDit
         nL26QoDfTwd4BQ3JWbZQ71Dw6dOArzwYIWmLN3a0gXKmzcznO8kXf+prk9VCqR3bCwMh
         wK0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxJY5LQ9HkJTAohIMilGhrsJXnLKcDlh14kxxWUixpQS54NvYwO
	13JUNv8iJll7m5WWHA8J39U=
X-Google-Smtp-Source: AGHT+IFZP99M9k1Jmf+hJuqhyMvakV9D0pwtSSg66dGE8qr02S4ZbI4yHrGtHrMXaotukvyA85EOPQ==
X-Received: by 2002:a05:651c:198d:b0:2cc:c6e0:fba with SMTP id bx13-20020a05651c198d00b002ccc6e00fbamr6429408ljb.7.1704270014505;
        Wed, 03 Jan 2024 00:20:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1d:0:b0:2cc:c5fc:a361 with SMTP id b29-20020a2ebc1d000000b002ccc5fca361ls59385ljf.2.-pod-prod-07-eu;
 Wed, 03 Jan 2024 00:20:12 -0800 (PST)
X-Received: by 2002:a2e:be08:0:b0:2cc:cc7b:5d55 with SMTP id z8-20020a2ebe08000000b002cccc7b5d55mr6915773ljq.69.1704270012489;
        Wed, 03 Jan 2024 00:20:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704270012; cv=none;
        d=google.com; s=arc-20160816;
        b=N+Vd1xfjxCAcVCpOwR4jY8DwCD4VprOwXuq91QgkNCQarMAUq0wL9VRrdNIbaAgcmR
         Vs3qktc0gKt0ZE8GMFBWjJ8eYnDp1VHZg4mAut+xvDVn0H748Qaw5GMjr/p6ce25ZqbE
         t81nrzfXBXgEOHzeesLnhc+eal0VIwJGxJ9JuuuX6i+/MC53Qy4fg7cMQZp+paKEyoDS
         cTdS/ANcRevI2ZP6LJKAe7SiRaVtNgLXrMUcNiCGs2SjQWH9F3enI0mgJdkpI1O7jYjU
         QiSrNz4JBu2xgpHucvnUhxztxGBtcBm8jPSbMwH5tIbcjgMdAJlrE7hnVrpLOaWnHwkN
         ZY9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=HypzNisJ4hYD1dxdCae8yyBWa40JveYyCJa3YAaa4wA=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=vI6GDd74fdBOEUFBOgUgXNYkdjOgbU4RhK+EREHpz41IwledKYJMOetuuEf2bojPiX
         iu8c+i88g2Z9xOcRtNUa328lSsaYKvfROrYrIQOkjoJroUMcq7DklKGBsckiX5mcvHpU
         fd5UvjfQO8D8hxG7QbstecNer6aOprmYiE6/i844UFgpPxYPH5n+VIb7I3JWi6CIRTFY
         DNUNL8LRgVhwYqNSucqtLNQXoHY3M+ATQdQ4aAm88wBptAopCI5AknAjYHeV6HNxKdCc
         lW+IKIivYMk1C9YOEyL0zcMX5vuI+lzodE5RyFGubvtTZaSbJ13byskhzKTK8dcGgP6c
         vHiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id z23-20020a2e8857000000b002ccfd1782e6si262293ljj.4.2024.01.03.00.20.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:20:12 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B6DBE21E6E;
	Wed,  3 Jan 2024 08:20:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 14C7C1340C;
	Wed,  3 Jan 2024 08:20:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id dS9bArsYlWVOXAAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:20:11 +0000
Date: Wed, 3 Jan 2024 09:21:02 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 04/22] lib/stackdepot: drop valid bit from handles
Message-ID: <ZZUY7hOGtzRNHV_r@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <34969bba2ca6e012c6ad071767197dee64dc5723.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <34969bba2ca6e012c6ad071767197dee64dc5723.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spamd-Result: default: False [-0.44 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-0.34)[76.12%]
X-Spam-Score: -0.44
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=Fp8SPTGr;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of osalvador@suse.de designates 195.135.223.130 as
 permitted sender) smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:02PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Stack depot doesn't use the valid bit in handles in any way, so drop it.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUY7hOGtzRNHV_r%40localhost.localdomain.
