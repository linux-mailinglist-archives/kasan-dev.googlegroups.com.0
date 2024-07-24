Return-Path: <kasan-dev+bncBDXYDPH3S4OBB35EQS2QMGQET4H2INY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC9293B2D6
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 16:40:48 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-39947aaa728sf202855ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 07:40:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721832047; cv=pass;
        d=google.com; s=arc-20160816;
        b=0QpuIdpSy5rLgHgQGZnOXgOuvxE5x0+RjbcQPzEGCLDgfuN5t/hvgbrVnvNKfn/kvD
         4BaI+2FJVDiiISaCit4H6MKkomXkJynuWsNnsIBHKiJWEuq2I/11zbvjSqihHBFqTH74
         OeKmF/Pe8p5+rReWvHE8NsrmAmm9wOJUu5LXSdWloXeHrqZmYuZDNUowSmf4fEDy1Pwq
         l7oM2nXQLVrw6y+0oV4Sby1F/boWG7jSIkcT5POSpwFPF4hB9Oq9guyU2CYYWkMlPYpJ
         39kWv7V7EDy4JrutUM57CNrkBAvb1aK2fKgh8F/bw6VuFkC9CUNfELTk5J8PRy9MECRs
         G1gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=wohCAOGo/WY0S5dmUfxYiSXThJcNyeCoZ4apUYGvyf4=;
        fh=Sc60Sw+LY0FpC5jEm1OQKoEMaT7bkBxUjLMhbXt9Alo=;
        b=V2ONwmwx4Qva+hYsI0PuoSFIz2Lop0GYska749LjD6x4hFtM2sIAyh36aoaZTHlBaK
         RUcGX6yXYCTQAxnmf9Sy7ib+bMdj2Nxw94w5idvFFK6/3WBi+ADAXHJM76wlztIhZ3Vb
         Ka7lp4QrpDVyeNNXfXzmxnnlctEF+rdSiMopLW6o3Wzzh03DzpN4GhELt8ZQGW63JRRt
         NyiNCrI3amaN42y60TyOaxuQdkXLUnOpCQQqzdxLp4oKZKNsg4Xo6GRUd9iFq03X6ix9
         F0ARF9QW5JPrd5APinzQppjQEIIqawuwd+3XFyP0B3OKvfGxh+utgLQkHMgt6Vg3ZB8i
         4x4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721832047; x=1722436847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wohCAOGo/WY0S5dmUfxYiSXThJcNyeCoZ4apUYGvyf4=;
        b=d+Ibd1misBKyHlhEds38BxoTZYSYi2Qo6w9nWgRlwT8vVWygFN1nSQzDCEILNHAjgk
         VdOHrBN1eH+Q+2x1Hzk0fFTGi32yjuekEVR1XZl8QmbYQP+PLmjr6RBZ5Y/Tp0LFpyr6
         iA/f24t1PCBPZO2LA4ha/vL+l93VJ0goDMmtQ9CEq/WfYYmzfuSbNasmp5ClvrzwmqSV
         m1dv8mk/kRc5k6v6NmWgFn34AkIvQm2qaorg3I2jJegKRtEPQD0ZLlWYQaU2ZPmGxOdE
         KUPKDEiZLvUCsDcV4oQZ+Naa8VBCyEADSKlU73u6dkHibw/vn+UYPxLpqHJSGZA7rTaS
         P5fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721832047; x=1722436847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wohCAOGo/WY0S5dmUfxYiSXThJcNyeCoZ4apUYGvyf4=;
        b=qsQuduV705IXL4n15wnuN3mTAq7v/RiFDiOBDnG76CjI0dfDqe7pn32+t1ZSvATdaX
         637ueU54cVMsmexwaLcRvMmQbErKa8ZtE+35Ckx/1DacoFRj+Z9b/2W3SwGT2VAB0NtD
         ExetYAhC8twP7MkAhsW4yKdvkZNPff9LD2OpIYwS/re9gEe4jtsbL5+b/vDy2CzOUN29
         tgo2DmQJk0+bU7YXoSMAfoW58iVjiM+SS4KW4HebANOSQgmSBS6uG/op7gmYX5gLkWnH
         44+i5xBNULMJyOVTj1XyJo9YSzFYe0ZDbiecIpD2VKbESawMFZJw1pEDL5PKg6SUWdAZ
         /oxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlT5xnvhWNMsTWYZMPnzlVPz7l7C/EmYQqJB4MUvMZkZFoNZE0j5ANAQ79b1T3D68N9VF6aaQxwDWXQCI2EGyLaETuFa8lMw==
X-Gm-Message-State: AOJu0YzeOGSecaD727GnpnynuIrfuRR03smC5C2FJkaLe83vBsBSMItW
	9wXglgJEFIbQEhH28gEEnj2lH0puWvEn48S5WekC2YE1Xd1xo2jR
X-Google-Smtp-Source: AGHT+IFiOAT30W4ZCQNpk5MSCcHX+njoZbzKH9YYqHoSCx+Wopa1U7vUL3k/fzzQpUZ4fN3c4q88/g==
X-Received: by 2002:a05:6e02:184e:b0:375:ee62:5917 with SMTP id e9e14a558f8ab-39a17d5c131mr4041675ab.6.1721832047263;
        Wed, 24 Jul 2024 07:40:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:106:0:b0:5c4:40e9:9160 with SMTP id 006d021491bc7-5d51a246fc5ls6299037eaf.0.-pod-prod-01-us;
 Wed, 24 Jul 2024 07:40:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU50g/35hJMsmH1hoKnvH12NjpDOhtnilgXuDdxWRZLSh75zmzy1va0l91n0G3EUfvdZYX8gLx1yXeaiP9waWkd9OK2kQ0z2wYbVg==
X-Received: by 2002:a05:6808:f88:b0:3d6:2f50:5517 with SMTP id 5614622812f47-3db08eadbb6mr2461850b6e.1.1721832046215;
        Wed, 24 Jul 2024 07:40:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721832046; cv=none;
        d=google.com; s=arc-20160816;
        b=RCNHeq60HW0lp/SpJY2emcYxDW0tIwa1pqXB0opfwczFUYi/Luv/CSzG0RT2//zD6l
         m8fLyKQ5xl0ubYSRhzKm/DRgzwKKB+p6kJu2BiVw8ghEZgfW9vyfl26Lqlt9VSSTb54i
         VB4D15GGhtOP+QOfjeRrUDnPtq/yfBiEwecV2irIuP+ZnlXOGB+REWdF5HQwQPmqQWNs
         OeLEnn1OrsFYtixubvS7O0vekCyU0bBoeHeNLWXUS4SaP3sA65DHkDFDHfL4qewcjRwq
         o6UKzOCX19k4RmZX7XVPBX6Z3AUtN0EymzZofTR13N7epuNIVX+ceadU3L+3zUkl3Qgt
         FQdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=K2oU6KeNMEKKrmlqYMEEXIL0CAP2uyQ2NxyjtiwdL5s=;
        fh=Az/L4DZ7Gk9UJi0OGNsqGxnJTnMNLUog1TSRzF8qb7o=;
        b=XE6Zut2VAgsTp8d8pCwddnX6FGD+vHVW1JDbkQZgdel0RUMi2sVWs/dMuTVAf7gD/v
         tqYDWJ6P7uiZhr1Q05YCPyPTpZWppM4FsSRhV51BbMIOds2xpTNzcUWE2PREd27BEOR1
         rqifR7NGc5ZgeZfKImi7hcYjyzbhHfJqyWGKKrcGj/5XsFFCh2qMlxHxjXU+p/2JyoPe
         /XeSK3uELJhRdf7hdwhP5bih+pZcpMJu51cPDtFgK533FMWSOQJcZrUoFU9zQAM/7fIl
         88Rf064WyYDaprwbtuTwqvaI9sD51litELOtzlw74xG2UMj+fU1qT10RnQ0QWuHHbUeV
         0tgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3dae09d0269si536158b6e.3.2024.07.24.07.40.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 07:40:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 64F991F7A8;
	Wed, 24 Jul 2024 14:40:42 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2C05813411;
	Wed, 24 Jul 2024 14:40:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id fARjCmoSoWa1KQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 24 Jul 2024 14:40:42 +0000
Message-ID: <38207d5c-c052-4701-8ccd-fe6381a97194@suse.cz>
Date: Wed, 24 Jul 2024 16:40:41 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: paulmck@kernel.org
Cc: Uladzislau Rezki <urezki@gmail.com>, "Jason A. Donenfeld"
 <Jason@zx2c4.com>, Jakub Kicinski <kuba@kernel.org>,
 Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
 kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
 linux-trace-kernel@vger.kernel.org,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
 ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
 Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
 Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
 linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
 netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636> <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz> <ZnVInAV8BXhgAjP_@pc636>
 <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
 <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.09 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,zx2c4.com,kernel.org,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	R_RATELIMIT(0.00)[to_ip_from(RLr583pch5u74edj9dsne3chzi)];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -4.09
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uavkczRl;       dkim=neutral
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

On 7/24/24 3:53 PM, Paul E. McKenney wrote:
> On Mon, Jul 15, 2024 at 10:39:38PM +0200, Vlastimil Babka wrote:
>> On 6/21/24 11:32 AM, Uladzislau Rezki wrote:
>> > On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
>> > One question. Maybe it is already late but it is better to ask rather than not.
>> > 
>> > What do you think if we have a small discussion about it on the LPC 2024 as a
>> > topic? It might be it is already late or a schedule is set by now. Or we fix
>> > it by a conference time.
>> > 
>> > Just a thought.
>> 
>> Sorry for the late reply. The MM MC turned out to be so packed I didn't even
>> propose a slab topic. We could discuss in hallway track or a BOF, but
>> hopefully if the current direction taken by my RFC brings no unexpected
>> surprise, and the necessary RCU barrier side is also feasible, this will be
>> settled by time of plumbers.
> 
> That would be even better!

I should have linked to the RFC :)

https://lore.kernel.org/all/20240715-b4-slab-kfree_rcu-destroy-v1-0-46b2984c2205@suse.cz/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38207d5c-c052-4701-8ccd-fe6381a97194%40suse.cz.
