Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3MK6OXAMGQERZ4ICBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 283FA867D7E
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 18:07:58 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2d240155a45sf25568631fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 09:07:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708967277; cv=pass;
        d=google.com; s=arc-20160816;
        b=jEoN8jahVzewn74LGyaanbtiH6sOZEYD+2lNkHNDqJO8xUfGZZGt9Z8uAO5LCXOWnM
         wqN2cQVouEkbyPnsgNIqUTkZM2KrUqMHP+nK38VarLLMaYVCCiMbyAdCQxW8H3crT4R5
         pl3EMBii0KrqA+V9HAp03Cmk7QE/YKuDtgYyxFtZ0HbSxV1byx8Wqk8Rl9uSTJm0xyNT
         Qyt5o5AhbdnkUv/cL1udaIkWrwaOYP+s0idrGHxHKeznVEqqw6RqCc+kZcTdrIHKDoR+
         kW5KpTo60ViTpHweYY9ghMUDnktEgGKekUYS4mwGf2BlYqpzY6UJwFIHfW1m1w8xMHW6
         uixQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cgJbv1Lu0LFFGCnTIK/hpol3lPxV3OcxZM9EJ+XggOQ=;
        fh=QcjoeerJZcwPyx86Tpidrjvs6/U32kwkXorYecVopzI=;
        b=iTTiHi8hQPVbOcat9yjGrks89nTwD6MsZq9cSrRqk/QINME71fXC+Crlq5n6Nft4RE
         RLe1upRSHuA9KyPv0Pf50p0leqfYFHAEgBAA13qjREGRrF8uWQvtT/6n1cih4jiGSM2x
         TG+AliJoauYpDrNlyogj0S6Yw4eZqR0WG5C/9/HT+LNVolB/VZ9h0M+rA0HLylfYbhIa
         OiBmx1K0iVsBWofLMGSL0z1sYoLTeHhttjWDxPa1IlYdb3YRCKqo1cxVQuqQCNBlvLhE
         N0XwQSePLxp98/K+gysDhcMyoFhgs8P4zw+HKcOjEQ5RfVfN5lp9BoYF4OJjU2vJwcUS
         I3/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708967277; x=1709572077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cgJbv1Lu0LFFGCnTIK/hpol3lPxV3OcxZM9EJ+XggOQ=;
        b=Mm4JOGLitaDcJPQ1gT0ibpVN7p5t8wfLgEBAcyRccFkxZWso1VS81unL775huKCoAE
         ZauguGz4h7KbwLxhglKSaB5TsJteNRQcBt4IogEfpJst3PqbEAHFZQdKmVH2AMgcFm3N
         1KVWlAUceomUbcM7tlQgjFK6Gf+RDroP+1o+xJPYCyMP2uTSX5UgrtDz3Hidy8ZWrBEm
         rJZk4UktZFC3nBf2DLC6zcsv8CpwxQMx+1ltFBYH/wqFZDLukuLteycjMdiRizXrxkYC
         5R1cuTsVpZNP8ix3SXQqWpwEPd9y3bOaAXnDVuVXuf6fqtqBDWpVH8MwNlkp1hQwObkT
         UZLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708967277; x=1709572077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cgJbv1Lu0LFFGCnTIK/hpol3lPxV3OcxZM9EJ+XggOQ=;
        b=q+HD12hbeqq9FpSSPkEctTUzFnHJr+DX7eVOhcnjAi7RDWy9Xgj3n/qnX3WL3c+IBZ
         UZtWcbySJABYTk4yu0U2ue+VDTEQJIVTNCw688j9MQi4+J47bo20UBKil94wp8Us910M
         w2zD+gH6KczcIWZPyzCo5NYu50BwC7vVKZHaaurYWk/taTKHIZUqx7NXUdp3Nd8lX5tR
         Ngjg40tx8zu3cX4gYBW4Q3lrfuvAlrbf2+i3z+2KoCbykf+kW6KW8Ze/JH7lZKBQ5AJD
         te+pZKOcmx43QouRb5PwnCrVAea4DLARl1EiKC1mTIyFzEODfOwS0ruE7m1K8K5bxQHJ
         kJpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDtYuOb/9YngoGpwbOrA+3hXl3JHZD0LtPp6n2cVTKZS8zinatVhM9S0HPptkqenDxwVFvyXfPy/WNiXJwcp5y2wM2H/u7gA==
X-Gm-Message-State: AOJu0YwuZW1fI0aFuEi8tQeA/NvF4rLizFKQvdxs6PbOaCtJ0gZDqEsg
	ILHca9xB7WZihLzifZANBsr2dzUMDKi81Q+tAUtKzB6dIgoGfa33
X-Google-Smtp-Source: AGHT+IFb1QIwt2HxzCHO5hMWJXidlo9lBKaW4PFdlxs2BoeObfVzPQTIcJ2k4P3eOR++5rZFVUZrUA==
X-Received: by 2002:a2e:8e88:0:b0:2d2:7d58:7986 with SMTP id z8-20020a2e8e88000000b002d27d587986mr3990051ljk.47.1708967277179;
        Mon, 26 Feb 2024 09:07:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e12:b0:412:a3e9:defb with SMTP id
 ay18-20020a05600c1e1200b00412a3e9defbls649501wmb.0.-pod-prod-08-eu; Mon, 26
 Feb 2024 09:07:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhzh+jjODWZhFYRYt94TFvngx6f0egsTsdiyicLx96XLjaODUaOjTXq4L6xuDZSh7mrOzjblALMaHnesqQvVIkOqLG42RntNtVWg==
X-Received: by 2002:a05:600c:4592:b0:410:deab:96bf with SMTP id r18-20020a05600c459200b00410deab96bfmr5831331wmo.22.1708967275625;
        Mon, 26 Feb 2024 09:07:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708967275; cv=none;
        d=google.com; s=arc-20160816;
        b=FSkCiLgTSIb5EiWVt/vutBzpJ55KmRLne7G72SmtxgI0++KnLe0lT9MCx2udSlKE1K
         YQXdK/l7zQkH2X4aURpBE5aUKji/0XKxt6ytDL0/9g/b1fapR9wvXxKY4Jg6KIakLIX0
         w23ic0Q8TOpPNaSr3T6rJ5kxzHhqJXjucNjuFwFz0ek2XL3VBNho2aTXLYl1xbzy7Srx
         NUtthlOWw9JUqjPLNCzDwveHN6MP8MN223dkTRk7TAmI0uopU7wbsM4Gih2fUxSQZbeP
         KTWfjD4faF2JieJrXlo5LuxX3d9RG8HjgXD9LstPj4FORJNry9it0xDTmwjXMVKXCLNK
         ohng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=I/hQUuxQxkgRF4bShVLMfZoPBj+Cztno3mv4Ida72ys=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=PIBKvSGHqPH6uN8Q7su3Y5F55n6W4cZweY9240GHYYcXyGKu60s9OlpFrF80oM3de8
         87ct/lMgQUKbRBmXBL1G/zbGeDr9Nj7LqYZMyQMCH4gmEmYOvNthTOEdyN48IZqdp7IY
         AJf7VShEdBnZw8PFVFj7pVrnD1QIj2c/b4/RQj63jWU3K1QZ84yix5LRY8AUC86IKlUB
         TDv99nXttvSwxWvJOEbpkh0pJHdq4t8iDmn9jBsaJc43SRd8HEbTyZ15tuOVZNJE6MUM
         LWOOzVX5LTGpdW0zz4jjuNK/v4pOTaCtKsZ4F8JLQWV8oO94LMgu9D0sFiSS6rwKpLTC
         bmsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id o37-20020a05600c33a500b00412759792eesi470826wmp.1.2024.02.26.09.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 09:07:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EFC051FB5F;
	Mon, 26 Feb 2024 17:07:54 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4DA5C13A58;
	Mon, 26 Feb 2024 17:07:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id qbR1EmrF3GW7GgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 17:07:54 +0000
Message-ID: <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz>
Date: Mon, 26 Feb 2024 18:07:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 15/36] lib: introduce support for page allocation
 tagging
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-16-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-16-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: 0.17
X-Spamd-Result: default: False [0.17 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.04)[58.13%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lqm7Mvls;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Introduce helper functions to easily instrument page allocators by
> storing a pointer to the allocation tag associated with the code that
> allocated the page in a page_ext field.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

The static key usage seems fine now. Even if the page_ext overhead is still
always paid when compiled in, you mention in the cover letter there's a plan
for boot-time toggle later, so

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d6141a99-3409-447b-88ac-16c24b0a892e%40suse.cz.
