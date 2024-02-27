Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLGC66XAMGQEJO3BOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id F0215869191
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 14:18:37 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d264c84b99sf33500131fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 05:18:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709039917; cv=pass;
        d=google.com; s=arc-20160816;
        b=WyIclcW0OiyXeZrj/R5o4A+oDTZFp1Yn+/5+3uCnNm+QzJVHYgNkt2yKRAp6vvFbEC
         AKPDnp6LcbOvXIzdgviXvcGw5gsbbBWrd8C1UmKN0h6UYY+viyL8rmg0rhQcOxQ7/lqR
         CyDzVPgdZgbFRC9JhtWPCZVB0WCc7F+J5qGseoeD+8a2UOJmlLL/9LQP0E0mb0M41MOU
         /iCddOu/pDF2od+rSh5UOdOhVSrS0eDvJ6+5+UweKX0YWPbXD89Qz/5Hq8A1riWda/On
         XQTzDUS6UC2BPtfRJhnUwWLyf1vJAlbvdH1pa1nOvMkk/eqADuhJZAfZqZaAD4lL0cm/
         lOEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=SLbghSWRNxFqvDGTRKyEC6jeCR4aDB2TmKPq5YC4gd4=;
        fh=XtpWjMaUl0sJhpvUcz5WvidxN1Uo3jqXAycrYThUmrs=;
        b=XYO8afvoavps51sVFHaDzfJc0vS6+dd5A/fzY/8oQCse08uZNZnlGVLIjjSPe1IlIe
         SZVNwh/ByzwY/98175kW0lrBAqTkkjoGL7MxKdrwinAeDPj6FwLFDY6rzFUDXrfjQqfs
         sF4KmyCfN1edLrWsWZyRY/FOQDgIuW4JbUoQrE6qMy8xpb5i6+r0H08EaIwLQ4MpIm5s
         ZqRHtBYWKfDagzHSuApMzMYgN2LHUuQyqdidfpn7lYsbhh+W2/1AAN2HV08IKeNNZS3I
         BtAVuxbz8HEH46m4fyS8HMFEJi0PS03sJ44YSbhQ89AKGbIxL0bC3qBRTZiAbgVE5Cyf
         2/KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t+9keHML;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F9IZKXKZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709039917; x=1709644717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SLbghSWRNxFqvDGTRKyEC6jeCR4aDB2TmKPq5YC4gd4=;
        b=Tpet8XhJ7w7j89NFAaqH7DiDDacSbIDQZPg4YWBiqWtCqW3mgDg29a1rBNasvd2/5B
         1PtqSW7D3uuZa1ifLWS7gN+Qv1ez/rBuy7aLQijS7ls4Z5hYWbb5N2/deHQfLAPde4KX
         3EMRUyjUf7bWmvqwkm/xXfIGNcMD0I3wt20nOBDPhVXUzgtV6V2TJc6T6IoQ4B/fEUmm
         UR6YmabRh8fH7k/hcdhEQYUXA2WwKja5FxKKHeTlxp1SqV1k7/kkBnyY9JTWcPBA+lmy
         TFQ/+zqV42/CgfC7n4W3MfXuUBH2ZdS8ZJSGLozPmhim8IrHHq1Whcw7kyzYbRxJuVCV
         j8FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709039917; x=1709644717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SLbghSWRNxFqvDGTRKyEC6jeCR4aDB2TmKPq5YC4gd4=;
        b=IrpZEfcOC27GJbHNspUIVL6RQo1X2WaYfrtdfZKEJ3irITf39XIxSWjmbxza8PmDpA
         RJttkOxbL217ilsw2Gfk1ysdhpMk3brMktV/yX9oaXeHsT/xdyr9UvrePlqy8+nyQP72
         T4CreurpB0Zm6uv52qVbNBtCMhFskQOrm7HXTYxb3VS2VKI+YWOnq737/LnDrdgqnXa1
         hDcetU6bEAYaGc7C8T8ZRL2NnUr7Gkkvh+3+BbEXCShLdPd/mrfAd9IRL4S0I4OJRQr3
         czG9YT/X73pozz/Wiixb9e/e9QICQgPvXxordd0dWfY88b27ilsQAzIX80SID3bWxM/X
         iZ5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWszzJtcUtgTbVxAqWR5V4WX8eA868A1xufKVWkecNg+MtOjjxz/A3VRtMbLIBrPQZ9z8+ZQTQpWSHSvm9J5LEDUJ87Hvu6oQ==
X-Gm-Message-State: AOJu0Yy3tbQhn+JSpaVQhOsQlYVI7sMaTidPIsFJsSuWU6pbsV3v2NWZ
	u+LwK4yAVn219tXMJJlp4v5J5MChlJUQRZZHYZzROe8Epl5fsM4v
X-Google-Smtp-Source: AGHT+IFIkt+ppBTqDm8BasMgXxbJUlQ58q6o9zs3i3CVDDZ0mXIRKW4E1lRgVH0JGDif1yRwANDTQA==
X-Received: by 2002:a05:651c:78a:b0:2d2:3757:c6a with SMTP id g10-20020a05651c078a00b002d237570c6amr4951728lje.42.1709039916846;
        Tue, 27 Feb 2024 05:18:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10a7:b0:2d2:a59e:dcd with SMTP id
 k7-20020a05651c10a700b002d2a59e0dcdls134996ljn.0.-pod-prod-08-eu; Tue, 27 Feb
 2024 05:18:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWKQLzEXIrKyMnXzVo8TwKyE5RYXgMXKZTn5Rlzii/Fron5Ri6seigKHWKd6ds6aDy1fqsyWcI+ICsl0jQB2s9N/AFvEPJWk0N9YQ==
X-Received: by 2002:a05:651c:94:b0:2d2:3d31:220f with SMTP id 20-20020a05651c009400b002d23d31220fmr5401658ljq.25.1709039914895;
        Tue, 27 Feb 2024 05:18:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709039914; cv=none;
        d=google.com; s=arc-20160816;
        b=NgJKeuEj3Fh9ZTBzeaz5+gJQAfEYVz6nK9Uxvpux3hgO7k4FtIIjiFFflxDTeQtcWM
         c6FRXnPMf8xeimyYUQPXoDAutUj7mPsCxYsmd1VNSGc8rv3Rr+F79tOVfZ7Q+GgUHR2X
         H7hwcWcS9Qmwu8f8IGbMZZULcvIQ4/CCeQC4qJMcDOn3NKN4kQBTf6j4jaHpsCHB7iHW
         rtrnzb0uFZehRXs7TYCtyX76Ztp7lvB8j7yNdQymidpULSiIIQkmMZhjoM05IepfOIwG
         hoB5yR4N0ZdXpXMIUcGwVG8cUynXD07JjOSArHV9zrj9qNuHTVNc0ucKrogP6jXJymia
         UdDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=b5fxnH3MZSXNsSIAXZNKwmzfwaEYfCce0iXFeFygkQg=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=XvEcBySLjTCFIfLPjOUYgChI0OHYpWwyhBdzgp+JtyJ/cAEuhPvWmec2qwg45k/kCh
         HncS3iNS6vqzqt9lP+lE9hIC8AFEfxJtctSgLN/ziUB1AmvQKDlBvrGi2O+EsYZG06Eq
         nAZ24w3MRj23oyLtUBurs5+dURvOWBn23Li94ghn77e3hiXBQeOdgGJxCiAbBIXAA1T+
         XlXUHDJLVZUUisTuPQEoX0/EYUcXH69wCDSXF9sNcQfa4r5QlIdEf0q8AfJgDYsn6aIM
         bNXl7Vl3WVr1poskuD0GI2DfjSewAIkpGfo2bD/6Rsy/qJMxxaLI0g0ptfQlb6gOwTL2
         oNRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t+9keHML;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F9IZKXKZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id d10-20020a2e96ca000000b002d2a3d0d3ecsi55346ljj.1.2024.02.27.05.18.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 05:18:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C6DE22229B;
	Tue, 27 Feb 2024 13:18:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 31E4C13A58;
	Tue, 27 Feb 2024 13:18:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Pt1+Cyjh3WWwLAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 13:18:32 +0000
Message-ID: <ae4f9958-813a-42c8-8e54-4ef19fd36d6c@suse.cz>
Date: Tue, 27 Feb 2024 14:19:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 31/36] lib: add memory allocations report in show_mem()
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
 <20240221194052.927623-32-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-32-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[11.76%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.00
X-Rspamd-Queue-Id: C6DE22229B
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=t+9keHML;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=F9IZKXKZ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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
> Include allocations in show_mem reports.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

Nit: there's pr_notice() that's shorter than printk(KERN_NOTICE

> ---
>  include/linux/alloc_tag.h |  7 +++++++
>  include/linux/codetag.h   |  1 +
>  lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
>  lib/codetag.c             |  5 +++++
>  mm/show_mem.c             | 26 ++++++++++++++++++++++++++
>  5 files changed, 77 insertions(+)
> 
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> index 29636719b276..85a24a027403 100644
> --- a/include/linux/alloc_tag.h
> +++ b/include/linux/alloc_tag.h
> @@ -30,6 +30,13 @@ struct alloc_tag {
>  
>  #ifdef CONFIG_MEM_ALLOC_PROFILING
>  
> +struct codetag_bytes {
> +	struct codetag *ct;
> +	s64 bytes;
> +};
> +
> +size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep);
> +
>  static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
>  {
>  	return container_of(ct, struct alloc_tag, ct);
> diff --git a/include/linux/codetag.h b/include/linux/codetag.h
> index bfd0ba5c4185..c2a579ccd455 100644
> --- a/include/linux/codetag.h
> +++ b/include/linux/codetag.h
> @@ -61,6 +61,7 @@ struct codetag_iterator {
>  }
>  
>  void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
> +bool codetag_trylock_module_list(struct codetag_type *cttype);
>  struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
>  struct codetag *codetag_next_ct(struct codetag_iterator *iter);
>  
> diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> index cb5adec4b2e2..ec54f29482dc 100644
> --- a/lib/alloc_tag.c
> +++ b/lib/alloc_tag.c
> @@ -86,6 +86,44 @@ static const struct seq_operations allocinfo_seq_op = {
>  	.show	= allocinfo_show,
>  };
>  
> +size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep)
> +{
> +	struct codetag_iterator iter;
> +	struct codetag *ct;
> +	struct codetag_bytes n;
> +	unsigned int i, nr = 0;
> +
> +	if (can_sleep)
> +		codetag_lock_module_list(alloc_tag_cttype, true);
> +	else if (!codetag_trylock_module_list(alloc_tag_cttype))
> +		return 0;
> +
> +	iter = codetag_get_ct_iter(alloc_tag_cttype);
> +	while ((ct = codetag_next_ct(&iter))) {
> +		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
> +
> +		n.ct	= ct;
> +		n.bytes = counter.bytes;
> +
> +		for (i = 0; i < nr; i++)
> +			if (n.bytes > tags[i].bytes)
> +				break;
> +
> +		if (i < count) {
> +			nr -= nr == count;
> +			memmove(&tags[i + 1],
> +				&tags[i],
> +				sizeof(tags[0]) * (nr - i));
> +			nr++;
> +			tags[i] = n;
> +		}
> +	}
> +
> +	codetag_lock_module_list(alloc_tag_cttype, false);
> +
> +	return nr;
> +}
> +
>  static void __init procfs_init(void)
>  {
>  	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> diff --git a/lib/codetag.c b/lib/codetag.c
> index b13412ca57cc..7b39cec9648a 100644
> --- a/lib/codetag.c
> +++ b/lib/codetag.c
> @@ -36,6 +36,11 @@ void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
>  		up_read(&cttype->mod_lock);
>  }
>  
> +bool codetag_trylock_module_list(struct codetag_type *cttype)
> +{
> +	return down_read_trylock(&cttype->mod_lock) != 0;
> +}
> +
>  struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
>  {
>  	struct codetag_iterator iter = {
> diff --git a/mm/show_mem.c b/mm/show_mem.c
> index 8dcfafbd283c..1e41f8d6e297 100644
> --- a/mm/show_mem.c
> +++ b/mm/show_mem.c
> @@ -423,4 +423,30 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
>  #ifdef CONFIG_MEMORY_FAILURE
>  	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
>  #endif
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	{
> +		struct codetag_bytes tags[10];
> +		size_t i, nr;
> +
> +		nr = alloc_tag_top_users(tags, ARRAY_SIZE(tags), false);
> +		if (nr) {
> +			printk(KERN_NOTICE "Memory allocations:\n");
> +			for (i = 0; i < nr; i++) {
> +				struct codetag *ct = tags[i].ct;
> +				struct alloc_tag *tag = ct_to_alloc_tag(ct);
> +				struct alloc_tag_counters counter = alloc_tag_read(tag);
> +
> +				/* Same as alloc_tag_to_text() but w/o intermediate buffer */
> +				if (ct->modname)
> +					printk(KERN_NOTICE "%12lli %8llu %s:%u [%s] func:%s\n",
> +					       counter.bytes, counter.calls, ct->filename,
> +					       ct->lineno, ct->modname, ct->function);
> +				else
> +					printk(KERN_NOTICE "%12lli %8llu %s:%u func:%s\n",
> +					       counter.bytes, counter.calls, ct->filename,
> +					       ct->lineno, ct->function);
> +			}
> +		}
> +	}
> +#endif
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae4f9958-813a-42c8-8e54-4ef19fd36d6c%40suse.cz.
