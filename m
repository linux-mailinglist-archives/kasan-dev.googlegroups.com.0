Return-Path: <kasan-dev+bncBDXYDPH3S4OBBGHG7OXAMGQEGYJZRYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 501B486AA59
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 09:47:22 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2d2b9aa4e35sf4535411fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 00:47:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709110041; cv=pass;
        d=google.com; s=arc-20160816;
        b=vQTVS5CTn3Pd/etYaIeSOAPPX1Qr1dmejweijPRoXx/c9PMp/dutWo0lMUiRbxnar8
         nFywlvVh2XzG56hZkCtTVnuCT+0dDAoszmKGatMVyyIqtZpsYAAqRtyNZujY971Lwk7a
         s5rYrXXUsmQeywjrLqjar1XYBc3/oqFhQSHVQrV3V7CoW8u8+4zNBkOOvhyuHdRXkyNi
         vJ7AFloUvlf5sLopXxbf0QocQ6w/UexLZElOpLwSEOMkBCnFwECmJ0OEROQZU/1QeQlC
         SG/Qsqr2Izkg5tfTsudFp1W5MlwA+UqBvzuApyBf4hxr3prmjpqZneyVOXWscwFbRKEO
         DKkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=mnr4H+dGJJczG3NyWlGp5Le6UyDZZb4+d/CfR+XO9K4=;
        fh=KT1+5Ds2Cc0BbxlJfgj3fa2Y41LtyoFu88gfX1IvXJw=;
        b=WatwGkPYXM2YkJ4/szXbq4J2NjYPmfNPXTBni3qxz4yFgYB7I6eS3KYCJYyeibmk8E
         gPSrAzija0NArQT8bIw2m1LArhnQdl4GWDeFU6m7CR14/XKBwHMFps5F48/LD+piGj1N
         QzJkXVlH75BjvgDcQ5J7F4oB4ogm1Lqs+kJInXf/C0TVtFkpgCJ1S2MVnpA6itF2YZR1
         EvT8Kd3qM2l6jd4AF+fjzt5u325DBbM/ZkvVL5XUfhmGnf3M5SeRiyLxK8eTusiwJhLS
         cxudnCLymT5AM7dCTke6S09xmiDbZx+AUBxUN+nh9Hh+4gjsdWTI6j0BTJAbPbxPrrSS
         O9Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;
       dkim=neutral (no key) header.i=@suse.cz header.b=A7eYUasH;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709110041; x=1709714841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mnr4H+dGJJczG3NyWlGp5Le6UyDZZb4+d/CfR+XO9K4=;
        b=k/EsiNA5RQEBUnZRcxvhnrV6IUx/k8jVEbrd0Y6tWJSmyJMfmu0Ki5HligXzcyJ3kf
         OGgDPq7wNswy6fomjrzQhhdoLGg1cCwBjHEbaRXs1ICPeZ9OqLMTrooCAwrmb30SwJe+
         x/4vdKXY5uaBsSmdEIPRF6xT9E5/9ibaddN0r2UVGT9yVgIyboih1C/p4RfIHIcm6hIU
         /V0WQJyCmnZ5tnXzEKNMQGC9q5hlQv2K9RpYSsPsIRfH5Jv5w3NCi5aqcIvNrqqB0L0O
         j/UzduX9uXfTaW9YI7RIhNfp04uE7oJ/+YGp6VGoLrk1q2F9xe3GClOqOUTey1ZEAnkr
         EVbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709110041; x=1709714841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mnr4H+dGJJczG3NyWlGp5Le6UyDZZb4+d/CfR+XO9K4=;
        b=IJMErzRftgChoNOs1Oq5WVGE7s8M9NDaqqD9ZqSmdwVjN4URSLKF5JOsgKpnE8gk7V
         7r3oVaa9EDsOv+MCbjVV0HB4MPAixye7TsBBAN2LX87J53ynJl1VxyZEhA5RwZVWgPpu
         Ut2nJYZopZ+0+pt5zPqMj77k5gANRIh1dXUDSS4KAgelZTbkqal9VBwl6+dSU8mmQBk6
         u6VB6uYAdSa7SE4h/4yBN+xQD93WHhXEpDO5U08uNoGf0Ps4egPhYsuJr5dtIbcYB7Pt
         3CGIPIqFGwoj5yFCB6hRSSHTE07iCTB0njuEgyJegGtQPMl0iCJexIy1Q/au6tIDFzXu
         UgFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULGmBBsM5iU2tIuErr4Cbke5qzK3o1IXjx+iX2ZD5mblYQgWCjFpgg0pqO4cG5lGY9B4HCzhhDFNm0+Cwy9/bXZdqzm+/Ixw==
X-Gm-Message-State: AOJu0Yy9HrbajEPyAhZIRb1/lIPcwpqcbgi1c1LPwzSs0d7Zf9/qLtxS
	/ihinivIxNB66zlod44g5NkXcC/HFnZEbnyXy7zbQCWMYZRABWpt
X-Google-Smtp-Source: AGHT+IF75B8OECIxWrb2MyG0Aq0Hw1EK+8IqJoeBoFVzSyeuftItrMyuO7tZDuVxrgZeABx+fjqakw==
X-Received: by 2002:a05:651c:231d:b0:2d2:3db6:b168 with SMTP id bi29-20020a05651c231d00b002d23db6b168mr6463358ljb.14.1709110040878;
        Wed, 28 Feb 2024 00:47:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a236:0:b0:2d2:8e44:ba5e with SMTP id i22-20020a2ea236000000b002d28e44ba5els200069ljm.1.-pod-prod-06-eu;
 Wed, 28 Feb 2024 00:47:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVTgbOfuOcJyM7qy8hN8VNjvwJVRi1UCXb9Qsheln235xQwyQLsF9oyqM9v4AXc6OIVOQsqOkNKmJS1SBpaQzaxRMNbYIYqk7Ii4Q==
X-Received: by 2002:a2e:a0cf:0:b0:2d2:a2bf:4ae6 with SMTP id f15-20020a2ea0cf000000b002d2a2bf4ae6mr2683738ljm.31.1709110038936;
        Wed, 28 Feb 2024 00:47:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709110038; cv=none;
        d=google.com; s=arc-20160816;
        b=qJKqCnsY2yeye85hX/oKLb3rmYQNPMUf7IMbEkRBVkO19V3OQtJ2HM+TEvT6YmcxEx
         pE8DchWvCPmjJYPaJpxHL4a3sEM4J/OcZlSTLVAPSi2+vl+EsMxqnbPu4PnNiIf/iIuR
         NdRjmeHOewgZ4bosaldq0KwWMgsYJ3NGReDa4zN/9s/dRiEWvScp/gYeSZdpzNabCPGN
         4tbDdwvwZl5LE0y/EAZx4tIVSbrGsfgOZyUk5rmjzVVWMDbWZLroT2rOpx4KVAv1Ulit
         VAgTwsOXYRZsintGRf/lCNJHmucUmWNvItDRPYcEcguOURIGd3lw9YD8nQpek+SB2VQC
         BX1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Vj8SBiVnmCzYeLcoo696dWgrqk2e7VmSkmzYdiIhZIA=;
        fh=dOHsy3mSRCJvTZwWeFaoCuCHq/O8VVJOOHQkFc4Oa7s=;
        b=JzMfoUDYjW71Ut9JXpw+PvmMkiQPF+qMiEI9eB4ly9tsjiy32MKKM8aREgpsjyAILT
         BnX0NtiIaz6BHnfPyZFFNH7i9qL5QUbovg71l5RnJE3lA+jJzM4gJGXyryR3N0nTJmZJ
         D7V1jKpn/RoNG9dQgcX1sE9IWgD3CLm2hggIjX6Cjltz3ZT5Bi5kCEJJSfkEW05xxZ/S
         MhzXky+vTtmG59pnPIQNxePBHf5NBHqff5zX9zQoWMcPtGfZChwTHfgEHzOlXTTta2Si
         g58FSbq/s8eFR3WtYQSRI/gxIHUfLBEsgR6Jdk6vKiXG1J5o/7kJS+hXOwwWDxCC/Cj/
         0mjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;
       dkim=neutral (no key) header.i=@suse.cz header.b=A7eYUasH;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id d10-20020a2e96ca000000b002d2a3d0d3ecsi181034ljj.1.2024.02.28.00.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Feb 2024 00:47:18 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0905721FCA;
	Wed, 28 Feb 2024 08:47:18 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6D9ED13AB0;
	Wed, 28 Feb 2024 08:47:17 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id d+w3GhXz3mXBIQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 28 Feb 2024 08:47:17 +0000
Message-ID: <6db0f0c8-81cb-4d04-9560-ba73d63db4b8@suse.cz>
Date: Wed, 28 Feb 2024 09:47:17 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page
 splitting
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
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
 <20240221194052.927623-20-surenb@google.com>
 <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz>
 <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-3.30 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 0905721FCA
X-Spam-Level: 
X-Spam-Score: -3.30
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;       dkim=neutral
 (no key) header.i=@suse.cz header.b=A7eYUasH;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=s6ogdVMW;       dkim=neutral
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

On 2/27/24 17:38, Suren Baghdasaryan wrote:
> On Tue, Feb 27, 2024 at 2:10=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 2/21/24 20:40, Suren Baghdasaryan wrote:
>> > When a high-order page is split into smaller ones, each newly split
>> > page should get its codetag. The original codetag is reused for these
>> > pages but it's recorded as 0-byte allocation because original codetag
>> > already accounts for the original high-order allocated page.
>>
>> This was v3 but then you refactored (for the better) so the commit log
>> could reflect it?
>=20
> Yes, technically mechnism didn't change but I should word it better.
> Smth like this:
>=20
> When a high-order page is split into smaller ones, each newly split
> page should get its codetag. After the split each split page will be
> referencing the original codetag. The codetag's "bytes" counter
> remains the same because the amount of allocated memory has not
> changed, however the "calls" counter gets increased to keep the
> counter correct when these individual pages get freed.

Great, thanks.
The concern with __free_pages() is not really related to splitting, so for
this patch:

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

>=20
>>
>> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>>
>> I was going to R-b, but now I recalled the trickiness of
>> __free_pages() for non-compound pages if it loses the race to a
>> speculative reference. Will the codetag handling work fine there?
>=20
> I think so. Each non-compoud page has its individual reference to its
> codetag and will decrement it whenever the page is freed. IIUC the
> logic in  __free_pages(), when it loses race to a speculative
> reference it will free all pages except for the first one and the

The "tail" pages of this non-compound high-order page will AFAICS not have
code tags assigned, so alloc_tag_sub() will be a no-op (or a warning with
_DEBUG).

> first one will be freed when the last put_page() happens. If prior to
> this all these pages were split from one page then all of them will
> have their own reference which points to the same codetag.

Yeah I'm assuming there's no split before the freeing. This patch about
splitting just reminded me of that tricky freeing scenario.

So IIUC the "else if (!head)" path of __free_pages() will do nothing about
the "tail" pages wrt code tags as there are no code tags.
Then whoever took the speculative "head" page reference will put_page() and
free it, which will end up in alloc_tag_sub(). This will decrement calls
properly, but bytes will become imbalanced, because that put_page() will
pass order-0 worth of bytes - the original order is lost.

Now this might be rare enough that it's not worth fixing if that would be
too complicated, just FYI.


> Every time
> one of these pages are freed that codetag's "bytes" and "calls"
> counters will be decremented. I think accounting will work correctly
> irrespective of where these pages are freed, in __free_pages() or by
> put_page().
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6db0f0c8-81cb-4d04-9560-ba73d63db4b8%40suse.cz.
