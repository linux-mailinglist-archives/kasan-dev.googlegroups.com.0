Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXVA7TEAMGQE53C5YDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CDDAC7410E
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 13:58:08 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59578f8468csf467959e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 04:58:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763643487; cv=pass;
        d=google.com; s=arc-20240605;
        b=hu/QEw3DqOKxqOeqHA8G57q0LrkGN4Vrx+lzVvCvJdFRLqzrXtMmhbku5exkaicqw5
         k5vzvdS8y+i12nqDInare0Ppd6K2R7zY22tCsVGkR/j1pgxJdpjUnHLyh+/FlbOwoEDK
         fDdULNTyXiXJrVYIyiH5vjn1MKOmDezfxXvQrNWUdlXltcwIxpPazwiSZx5fvUsIymz9
         w3/o2ZfAYluvQ8Bp3SPVqZYQwZqKA2eg9VnB4I5WDjeH4ytb7PQJYuDDxhrLfO71XTqy
         OKdk1yeRo7rhmmbaFj7aoTUPV6dQ519p++fJrXS9wWnYz2vLP39vf+B2nL7SxJnLPN67
         0D8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=iSlU/Ob4zwS1Tu7PqrIXxfWpUpfVxONT1M8b4kYME/8=;
        fh=QahTAbwKF7Nh3hqD9cZwnZK2sg3hls6QL19loL/ioe4=;
        b=F6etSnxV1EkXCQGVz20RjaLEKH4s4s346Zj5HPPHlS4Yrg0h/jHL674C1sKDA4DChB
         rULkoHApJu3wm6/lwPUvPkwQf22SdcJnXZnEVyh3HRqWNvkn1QMd3Gu0Rf7X5b1l0Ruq
         fVpYJdcXFp3dnxYKei+Q6M3TN1hWSgo5IlpnBukQQCtcIx7TroXuWmgNetzeK7EtUQIV
         F7r1llbmy5MQLFHH9CXlhS7V1jIsoh9Nlfk3JbJA3ipKbTukhWun/t5BOK22VcoXdbVA
         Wo7OFzkCtoltufDPb2bqYNk0rT7VLefDm8FyNZcJVcuctx6bs/LiwkB33RE1HkzEzc46
         5rYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KPz2W4il;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KPz2W4il;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ti84snLw;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763643487; x=1764248287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iSlU/Ob4zwS1Tu7PqrIXxfWpUpfVxONT1M8b4kYME/8=;
        b=lrEkv5y8mkUPEXbhiEy0aIZp98YxKp/5a877rnnvNYrJLd5Z5wsxtA72RDZm4P51AV
         lT6rE9lGePZNEIeGiXhaLJg6Nyy/yZ+XHh9MqpW2B5tedGR7k04HYo6nvf3cFFos+o/q
         cED9EJGEzr9kq7o8k6Pj1ec8eHY1g8Qhkq9goCUGeYt22Xj13wutG+m+FBFLOrp0RosR
         pxF2Sy5LRTzmPMYYtbDkpnDhzYwiLJi4wUfQ0P0p/GhqmCAmlVChtfGF3Rg19hx7zLHw
         5oHgEoERROs3CrF2LNciqRQCNFpeRBUZMH/bvpQnOXXF577/ZXyPaVAufdAcDaxJK6dn
         fRXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763643487; x=1764248287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iSlU/Ob4zwS1Tu7PqrIXxfWpUpfVxONT1M8b4kYME/8=;
        b=KXI4NkZNfZ7/tF83OOJZhoMPFq+aK1/YZBt1tF8n6YX8wnBfjwWtJrMgIEiMeiVKp1
         VgfVRN/iPlVlBKa8TlZnuHRmVHbTV6p3wB2ivo/eQVhR9lntGOgRdo3vEAAb06kOhX90
         9Jk77xd/Uih+IU6iP9vuIcHRZTKWaPJ60glKTKXOsUH/fYPexmTSaIKq5XT8UN22P+8d
         +M3htiY3x1TVArfqVZW+dHN6ie94qo5OjblFGgdbUKDeIXHZ9LoKKaeuns9PUJklcIfx
         +OIA6Xx9ZvyJ+8tXbq+xJgWSf7F8qmNnIOtPNN4bV+DxyDvChW+JDBVc/P0yOo0CRvwN
         WUAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAe/jZ8d44wfR09ffvn+7wttrBQFrWqM/OJ3Z/DWLP+ZwKYnbqJ0/tWSHuiOAPn6fB2B980g==@lfdr.de
X-Gm-Message-State: AOJu0YwbEP+YuK4wjKvJ690d6nQTOn+xv8Be3RaZytWTndPmcgCuWKHG
	BRLM/VE0u4n718xzf6/4382jErMG6ZmKcBU4bcHCzs1X60tXIYKfpEAT
X-Google-Smtp-Source: AGHT+IH6wadQ4yV5qDaZ1V+Uv4jY+2kfYeIklRL6K2rGdYT1c+FPZ2ovS+Vy+Ks0OPm1r8ueCQkcDA==
X-Received: by 2002:a05:6512:4025:b0:595:81e5:7556 with SMTP id 2adb3069b0e04-5969e2c2bd2mr984676e87.3.1763643487107;
        Thu, 20 Nov 2025 04:58:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b4BvAIW+pYBulYyWMi1JNg/Yi/Xwuyh1XJpfjGEqrcCA=="
Received: by 2002:a05:6512:40c3:b0:596:9e9b:d1bc with SMTP id
 2adb3069b0e04-5969e9bd209ls162085e87.1.-pod-prod-03-eu; Thu, 20 Nov 2025
 04:58:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU5vzC5qkV3C/HIE542szr3874DejEvV5/FTLOpn1NoRuH9V9qvrvtNSG/p3LtrOoW28AisP6IthWI=@googlegroups.com
X-Received: by 2002:a2e:7808:0:b0:37a:2f92:3bdc with SMTP id 38308e7fff4ca-37cc800e035mr6029541fa.17.1763643484109;
        Thu, 20 Nov 2025 04:58:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763643484; cv=none;
        d=google.com; s=arc-20240605;
        b=gB0vWRoKWbMiETyTRhz+J2tYiCBenkWsmsI/1huGKIEpXWuwCJZeAmjZ1VIjvcgt1Z
         5LY/1ydH4JTFwOtGzb5ZSmohjE34Xf1hvC19gCzs9DMS4ECJUTCSuQ7kHO/F6WSOe0gV
         VXlpoTH508yM7Wze7tSx/Xjck9R3nx87IAxknJVHmW3ZcbW4hqygER8nI1PQbOB/ydoA
         5vdobAurCBuZoln8ZdkEqFxJxG4o5KxFh+CNXvq41OKPkeJr3ftxBGR2URNQtbSucgVg
         ow7EUIOuAwREtbPpjxMQqxdhiugzhGdUnajJPdYK0pKavnQOqeFNy+2frdEleRE/ReR7
         E/MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=ZBU/AsUgcSzrIfqjUnDEsEXZDEFHybM/XjPFqhqGKmE=;
        fh=X0Gct2EHcBVCAlx1axI/Wui6z8Ur6tQqeRRVHGC4ml0=;
        b=N4UhW6m7FWl8XZH/aZlG+LMwKwhrfvJHlkI8reiLGKCFD9lXhtpURvPsTjtptHJLzw
         bpOP6d1UxAe9m+mu8oYOWfSkLCtEZeAgHKrlFH9lripeZ7h/GbPNCEzxG9/hoQAfDsqc
         b23Ra6+IKlzjyZPNxjhJgooWrPa6ShFm4QoURVsxm4s+x+HYU0SBvH8TnuewD3vbawmg
         eST9ZJRh9MfYulCQyZVzauuB+aLyyYfQWevyssydzeAF8YQFN8xvMbmx3bjMA/4RJJ3V
         zoNsiPffHQdkyERKtxrdMW6gl8RevzWOvg2hW9QNoxQMt0bCfIa8SG4lyh67xk0aWpq4
         SCeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KPz2W4il;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KPz2W4il;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ti84snLw;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6ba523fsi380531fa.8.2025.11.20.04.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Nov 2025 04:58:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1626520A2E;
	Thu, 20 Nov 2025 12:58:03 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EDD303EA61;
	Thu, 20 Nov 2025 12:58:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id T1iyOVoQH2mCbgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 20 Nov 2025 12:58:02 +0000
Message-ID: <7ffb1908-464a-4158-8712-7735100ae630@suse.cz>
Date: Thu, 20 Nov 2025 13:58:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [mempool] 022e94e2c3:
 BUG:KASAN:double-free_in_mempool_free
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Hellwig <hch@lst.de>,
 kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, linux-mm@kvack.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
References: <202511201309.55538605-lkp@intel.com>
 <20251120072726.GA31171@lst.de>
 <9e066a2f-28fd-4da7-bca8-c10f7b58f811@gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <9e066a2f-28fd-4da7-bca8-c10f7b58f811@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gmail.com,lst.de,intel.com];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[lists.linux.dev,intel.com,kvack.org,google.com,gmail.com,arm.com,googlegroups.com];
	RCPT_COUNT_SEVEN(0.00)[11];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KPz2W4il;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=KPz2W4il;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=ti84snLw;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/20/25 12:17, Andrey Ryabinin wrote:
> 
> 
> On 11/20/25 8:27 AM, Christoph Hellwig wrote:
>> Maybe I'm misunderstanding the trace, but AFAICS this comes from
>> the KASAN kunit test that injects a double free, and the trace
>> shows that KASAN indeed detected the double free and everything is
>> fine.  Or did I misunderstand the report?
>> 
> 
> Right, the report comes from the test, so it's expected behavior.

I assume the bot was filtering those, but the changed stacktrace (now
including the new mempool_free_bulk()) now looks new and the filter needs
updating?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7ffb1908-464a-4158-8712-7735100ae630%40suse.cz.
