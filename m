Return-Path: <kasan-dev+bncBCO3JTUR7UBRBFFW2SWAMGQE6LZFE6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B424822979
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:30:14 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40d31116cffsf75709475e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:30:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704270614; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7NDpHiBZbRC+WlFwIb91ioU1ZMU69LXGqFF3evdu89UYYsKWYvPv0XAFKaYQlAqUi
         3vPxF6itWZXQhT6nF4CvEo+4LJZ1pgw/bp/AVkcn5IDDaR49f0q+tOwX4McaVxyct+uA
         hIzL4D3tVy73PbKtdHrDsQ2ha2I3ywuZXNwcUOJy9UQQv0xttXYLIcQOCtk98xpM4+FT
         jZKc30ARD8rRlfg5V4pfv38NfjhnN0pYMYMFOhAZ/dgeSwx0J+EkAj1Jh2Oe8zKTVOHy
         t82DQURXge6D3BiH7qK3Ad9DE8yoSBnsxgFzcYoJjKINSP48SW2JPKgvqPqD5vNMXztW
         2UDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zaMflwtN+i7kDRoTGEyXy9F1TTInjtG61pOAkfGBWpg=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=l3uhCNu++uuskGI3yDfqeLwB6ejsDCrWLt32oTOE6/kQTkDbDYjW/IP/tdSP0zfQBu
         u1X+HmoM4XD/O0HPmGWYAGB0LFZot5pBtKqWj7IFDC5U//FLNjaq+ePg18zrc80iZliO
         zsh4ec1kA4z9s/HFoEba6Ev6zN4E30ra/CK0PfqGMNhhhjz0RlBOMqdvGgBadfa48eTT
         D8u+HoqeH8RZXTNMpS7LN7sYThnZRkl+D8X9QnvA4y9gAhnqvdOmy0yupzogC09asW7f
         Cur0diupb7Cfcy6JoL7HVlFkB69xwf2LoT0ChIY0o80nTMjq5aY69zNSciyToq14am0t
         zwrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704270614; x=1704875414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zaMflwtN+i7kDRoTGEyXy9F1TTInjtG61pOAkfGBWpg=;
        b=dNGiGhG8jGO45MPQMkuZKJedvIdjmTqy1Ik7yj9+RPCw1LWWHfnOvXlte0jqGx8H3S
         +dv40p6QsTKtP65Uj0NEfoZUV2cQoMkUX8UoqqhO0Jch91Rl1Ea827QcmjEx2qCheJM1
         KcdcKu4RhFBpo6EdZproTp9aIV0vKEr8rBFl8A7KRvUWTFaSe54fjnUNmXC0ksfdVwGy
         ZSIjkK7M7odHTdk+oUmktuEwsNKlU4Zzd2Kyi2g9Bfk1FK8oGyIEFuImhI1XPOEjGsMo
         0F/NFwy1nG6hzTd79i4T7Hl1NDEQ5CJqdUjn7xmCxVyBgI8dFoeRZFUz/VKnDe9ndqPz
         y4Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704270614; x=1704875414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zaMflwtN+i7kDRoTGEyXy9F1TTInjtG61pOAkfGBWpg=;
        b=wjyX1IZIcRx/QIyHdbIHG42/8Kp2sNjlFIvNJO1btltGbB7WhQ107JSMsefxDL/jEJ
         aX5LrUsW0EWBnCm3hNorBM5bDScoSGu2hYp3hzZmmIOSufvQGe3AsHrpjePm+E1L4TWV
         uqJSJOzrsMu0YCyxt/yEBylAiKOToUtZRRKMZHGqJdYqxjHUbjfxO5d08Uw3EHSDgxzW
         YI5j5gzNIg+lIzmMBc73z11tc8n7ddmj8Go6MdkMl1BflrjlwCIEPYUnBwrrJuG5tudi
         lI3Gu8B1BcRH1BYGhyD0gA5ymqGGkZQXHAMfHAxiRDGk1Oc/GPm/UdyBhVJAtafV5E+m
         ACgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz6v7A7xSSCLqFyeAuF+yCc6G+EUS9+Cnt5LHkvbCg70p1JSrxo
	xiZ23NsDDtkip9vGsj4nm1c=
X-Google-Smtp-Source: AGHT+IGFvvE05jCwxpfnVRraDmQMqVSV6RDPwwU5BZM6kkA9WxerEzKIB0aam1N/gzahPxb0TLcL5w==
X-Received: by 2002:a05:600c:4755:b0:40d:763d:c7fe with SMTP id w21-20020a05600c475500b0040d763dc7femr4576989wmo.121.1704270613032;
        Wed, 03 Jan 2024 00:30:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1808:b0:40d:5e53:d787 with SMTP id
 n8-20020a05600c180800b0040d5e53d787ls3107697wmp.0.-pod-prod-09-eu; Wed, 03
 Jan 2024 00:30:11 -0800 (PST)
X-Received: by 2002:a05:600c:524c:b0:40d:2522:1164 with SMTP id fc12-20020a05600c524c00b0040d25221164mr11743685wmb.82.1704270611190;
        Wed, 03 Jan 2024 00:30:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704270611; cv=none;
        d=google.com; s=arc-20160816;
        b=W2YInIIi+o2QyyAes0KezJEetxps6IYHoAD27etAwpUuqqjIEXXol11xs4tSHgKIsc
         GddmY/tC4FO5hiI4VB0ihV6A6BQ7/JpWMjteM5lCq02ZnKXTKV4ace5MlLR8A0tF8tPv
         h3MWTRz4xk1MiaCWzvvmZb/2J/ODQwcpjUt+gahqeRIfgzFRN1hrfuJaM2DhyPRrSAvM
         poB3jrCm3U4NBV96G2Q9+yfgwjg51aelpPGt1EsG6EygPfxrbKQyvxdBDKgvfHsQFI1u
         kbCjyh9HAjaK/T8Dwba+m5s224a0tza+OrpgxBMR5R83tpw7eb8wF2HyBFkNOTPVKWd+
         rPew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=XqOr95siHnywoD7/KUJ+ty+J9r6iy/sRySCRnI6kD0E=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=zlu9qND6QXGmnqv7tPaY4qCp15D2DB0VFFz8M2LmyD1xsBpZjdtMcCyK9B12VdQ7Ei
         R1nTUvefAAuMRvqXfSdaq23kZhYj+fwvH3Q9vJql7pZlc9CtlLZRUElcWq0Il0lUVBRZ
         pL92NCqzeBrKxM8DbcyndQuInppigFD6qEc4Q2tLsjC9+IeNAdQiUxuk//jgWOaK8dwC
         hKZb4b3V6UCPTtIDQT2mtEVqnUFS5NHB/D5BSG8wulSOIdPhjGGFQBIOT66jmpBI9SDo
         rDk/n6Iak7WUc4ph8FrBnBLE77gfeYBz24mOLD4Zjsg0VCvPBzQsOv2zkacW6w9FfaVD
         53qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id p30-20020a05600c1d9e00b0040d6d74d343si108467wms.0.2024.01.03.00.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:30:11 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9CE3B1FD0B;
	Wed,  3 Jan 2024 08:30:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E614D1340C;
	Wed,  3 Jan 2024 08:30:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id fP9iNREblWX4XgAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:30:09 +0000
Date: Wed, 3 Jan 2024 09:30:56 +0100
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
Subject: Re: [PATCH v4 06/22] lib/stackdepot: use fixed-sized slots for stack
 records
Message-ID: <ZZUbQOqDGUWmkFFx@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <dce7d030a99ff61022509665187fac45b0827298.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dce7d030a99ff61022509665187fac45b0827298.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spam-Score: -1.30
X-Spamd-Result: default: False [-1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[]
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Q2/SuwAm";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates
 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:04PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Instead of storing stack records in stack depot pools one right after
> another, use fixed-sized slots.
> 
> Add a new Kconfig option STACKDEPOT_MAX_FRAMES that allows to select
> the size of the slot in frames. Use 64 as the default value, which is
> the maximum stack trace size both KASAN and KMSAN use right now.
> 
> Also add descriptions for other stack depot Kconfig options.
> 
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUbQOqDGUWmkFFx%40localhost.localdomain.
