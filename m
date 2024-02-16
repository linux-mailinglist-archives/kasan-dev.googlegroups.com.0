Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOHEXWXAMGQEAE5DRMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D209E857F63
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 15:33:29 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4120c9ee485sf825675e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 06:33:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708094009; cv=pass;
        d=google.com; s=arc-20160816;
        b=kCAlJpzxroPRav+4fCD/dw8e4gsRNA8aBy2Z9jSw9UTBvvREPW/k4u84wIQmSSrZzP
         bLQk+E2c6s4cshe2wDmqO22scKhlsmgbXTt1TOmo/5cpHf+215qMlcgMLiH5AWA0jl+x
         /WqFaltjiaPqLj9hmQ0n2/mQq5ZJ7vFN89f+QuY+1VWELv8heuVFk7bKbMZHeTsrMfEm
         9GPaDgbn1dZZI9G+4P5u3GZqFqEJJ/rITowAcCMRaA0FcR2rc4HUXW3uQelkyEOD/FBZ
         kMIV2A+t5jvTaFshBfX662JvGRQpe2OtRc5lzouahlHVtaVbr4F7+++VGhXyjg0jgWtc
         a9jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=E844I0ySo25zYd8UTW/pyAw9vtSyXbSX20kVfTzaXdo=;
        fh=vqyfVqlKcwoJhQeRC4NIafneF9iIbz7yyvw+NMNOfIo=;
        b=K41aAEDEoqu9t2JwVRRU75Nj8IvtdVAJVpLwUg1U+BYTMq6e2dzn2eP0zl1KTpKZZH
         WMdX9HglFUJYoMyr7gR8CdcSZj6zDumW2AVSLaWTnoySgNzOgqK8vZyyvXrTZ1vwwTc/
         OGvwExDwxB5upNB1vgrfu1RpLV51QAx7tmTEzq8ojUH0pY5mDBULozC6rNULFWaSNg6u
         YcwQrPg79+rNwMLeWRQ/8n3MRt5aG+1WYYjxSo9QZ9mFcIgzVjuFS6XOcSK/ww7mAfHf
         ornuUL94LXUqTcLNWAeygaovwIQaqsaAn/BINp1fvoBbJDUT1Bk4nVvrUg0CqwZp4sX3
         IxCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708094009; x=1708698809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E844I0ySo25zYd8UTW/pyAw9vtSyXbSX20kVfTzaXdo=;
        b=AUR9FovEMxYCElAziKZxLEC69gs5yshQZq5NGiXBQFggwDOHTjt+q4v8n+HHTITElw
         m8MXXFXlqI7jtJj7YV8rra23w0zbzMnFikNCDIUD8qOiaYmmPaSVbqSauK/gdAd3Mpcx
         F2nT+ICgQZMB/ZpRom7FBxMTKFj/GQYR78dOfaiHE7d9lwi80E3J6XlvRtWuOLi+4ea3
         O7h+GNsesDBVoUF90fpsCZmOh2uQq1NXO/BRI2C/UojyGJ3SkPyh701TTB+kvLIZogxD
         IkWDX35lvLgCISfb+btJ+XG9vzjwd0Xys+ChGmX5yDCxwASjGg161bmiyXKzTXzITITs
         e8wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708094009; x=1708698809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E844I0ySo25zYd8UTW/pyAw9vtSyXbSX20kVfTzaXdo=;
        b=dMeSJt8nPPDPABDNindq8zSAVlC/0udhyNfa20QkAz2JK7jPHJGxrf3TrBhY/2RBoq
         Tp9bbS9f2cOfxCDs00xAObviFqMBn/2I6XvVXR5cm4LqOxThXs7ewa1ld4Nj9jQK4unB
         7aupsfUzoUnUg5FVQoI3TNPrnqiwS5lkJFS3Ye7vqrU6NvLtqBmYrPz7bSgiHI2TWppp
         1sqfYEsPGjPP23KG/68gjasngJHeHimkcsGzKEhemLpVfVvZBj5qoBFT+FPhuZ/uB9Ok
         GXdliNk5bpsPjezozsqDV4to/uxBmOyNlKxeilnX28MPN3ybbL9jEaA0WqY/5DuKQ6Ra
         Xp6Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGyUR6xBTJwMPz/iwyg6TC1OPc2LKRHHe7k5ShKbW/UPyKhQN+3hFffo+GjpczOFkAanPKlKTwSyuloUdBfVG9UWx2xCnzew==
X-Gm-Message-State: AOJu0YyBiaM6n8a/7j9CFwL/9bRcj0EeVabghLz3q6TBgl4Oms0Yg+Zw
	KWWmsWOGlm+Rji25ZL4XCzVkyu7LhwO0aaaAuVQMTDW2KGBb342N
X-Google-Smtp-Source: AGHT+IFmazqrp0Zqr6LuLs/nv0Mq25vEkogiDkzIp+QwnOGggwcSPLgask/3WR7djlLzGvOk6T9OAA==
X-Received: by 2002:a05:600c:5190:b0:412:40fc:51a7 with SMTP id fa16-20020a05600c519000b0041240fc51a7mr142005wmb.7.1708094009023;
        Fri, 16 Feb 2024 06:33:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6648:0:b0:33c:e55b:f429 with SMTP id f8-20020a5d6648000000b0033ce55bf429ls273180wrw.2.-pod-prod-04-eu;
 Fri, 16 Feb 2024 06:33:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhdcqHlsou0Im97aLYF4GXoLQuXZqu36nGzptOLUYOUi5v96kVNkZJKkOCuYZc5UaFHBSV8wosFQpWTU7JIF29YmjPbK8jfw+L5w==
X-Received: by 2002:a05:6000:698:b0:33d:9f:efff with SMTP id bo24-20020a056000069800b0033d009fefffmr6220987wrb.16.1708094007307;
        Fri, 16 Feb 2024 06:33:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708094007; cv=none;
        d=google.com; s=arc-20160816;
        b=kj9d/9cZCUUQ3II9z2JaTtIPPWUTniDvkU3yku4gFvRP2caf/3gu39+MjEoXdDCdcf
         Vgak6o/ExE8cmgH7pxYyqmffio7p4ePnAyrnmVuf1k8Odjo0gRJVL2NVHDsVzr01Og6S
         TeglKxO8n84eebx4BGGeGOWUOlzPHotvX1j3sFpba8pLY+2wnGEUpW9aMI+gcUSSCSDL
         66rez+nG+QgLEn8uesiFRz/KEX7Szd56wwHWvivJbby67lpdAvAfI9/KcEMsQ5/M8Xs2
         wHcigo0Ulsqiq4nKB5tytnue3v3h4BXznCKcsBH0cNEQ6iWaekwTmYpf9xgZIUoEciIh
         suIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=bEShoLEM6tIkuBWHvdvzGbyhOUXhBWDe5D52MyLH2G8=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=sgABNojHDV9j+5YiscoR0WHx3TDTa67LD7fa8+W3SADbpwNl6/WSVMik/jl0y+dFA2
         u+CFQs3nnIXSu+SahkPyiLS9Xv+dJQIvXyAdfniwg2wqOevE5170OdnEhg1uwd9FmKg3
         OaAEU0DQ3PNkwRX8ZjmybpfolEYeJAMSYYlhxKKCQMJ8JcG+WhBB9ZBs+V/zSB2l/Ad/
         zWzf5LfL2lEWDBmcZi/a4KT7FNy8bELn801UZ8YXHgsbKxoNJhheOIzcTtgWrRG90dNq
         baErJMYEiLaIoxXWbD/Dvo4iEqRz0/+oIO3zA6L/CT+PVqZ2QGVFIouviUKpmrXSbUGf
         p0Cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id i12-20020a05600011cc00b0033cf107bcd9si59684wrx.1.2024.02.16.06.33.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 06:33:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 944A11FB6F;
	Fri, 16 Feb 2024 14:33:25 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E91F61398D;
	Fri, 16 Feb 2024 14:33:24 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id H1yWODRyz2WlNQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 14:33:24 +0000
Message-ID: <2e26bdf7-a793-4386-bcc1-5b1c7a0405b3@suse.cz>
Date: Fri, 16 Feb 2024 15:33:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 18/35] mm: create new codetag references during page
 splitting
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-19-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-19-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.19 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.01)[48.72%];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 MX_GOOD(-0.01)[];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.19
X-Rspamd-Queue-Id: 944A11FB6F
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rbn1NWj2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

On 2/12/24 22:39, Suren Baghdasaryan wrote:
> When a high-order page is split into smaller ones, each newly split
> page should get its codetag. The original codetag is reused for these
> pages but it's recorded as 0-byte allocation because original codetag
> already accounts for the original high-order allocated page.

Wouldn't it be possible to adjust the original's accounted size and
redistribute to the split pages for more accuracy?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2e26bdf7-a793-4386-bcc1-5b1c7a0405b3%40suse.cz.
