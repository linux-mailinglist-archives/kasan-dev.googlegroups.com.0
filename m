Return-Path: <kasan-dev+bncBDXYDPH3S4OBBMGX62XAMGQEYXUOV2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 44CE9868C44
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 10:30:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-512ed819112sf3044871e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 01:30:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709026225; cv=pass;
        d=google.com; s=arc-20160816;
        b=uj1jj8D5MiTAGSfz38Yoi6mCKDRsV04OmRBM4Z2LHecXqty+4lAbnkuS+lD18r2kez
         JgTx82G3iNBpg8fl/sCbnw8A4gw/XMeMqKFNepA0jU27GH88v+PiODc09P0kuNqeMUd6
         mrfxVAVHjOMuayCDnPrw7fzd7ppPADExKFqLrlEX5Ymv1Rl0LD9AxNYIAjaf7a9qT2Qx
         qkZvx1rPjWAi1aRi2gWjWy/ovyMzaTQmQfTHnuS1k/6zAsUElZTq9BWdhKsBi5FoQ2If
         TfnSBUQdq4SbEYaybdJY6SrxYSlfdBi+Y7lO1/nWvj37oWni92i8hf3KOblVpo3dho9k
         ANKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=mo91yDl2ymbVTks9COlmiRk05cIm9YtynpF1VS2/Zlw=;
        fh=61mqLtAviOU5E07M73wyalhRSD7zSRuOROqnZENFjq4=;
        b=qRkOedTJ6KvLaC4/sqKswVQ9tuo7GbJ5D9ih+JQ3NruwHL14WZNhsSQLTGXfe6Jsq/
         VCoHdrUUxTWfH54nMKUvXUAL2Lc2GHYspm64Oo/AKY7q8CStc/qEl18rk6aZOhLQ53g3
         q1eXemIMjQIZrOu1z9XGxIix64eMYI4QW7vzehpe+VDXjsPlj2HFX4VbbBOf8FTN1ygV
         6H6ySXkKfJ8ewBiSYR5nVKuD5iHO5xrfSdgryFJS7oKdjG7AdUdMcTNdBS7JRsP2p84O
         CaGQPJVC8JtYSOz1PP58bZbN3HeuetNXsd7cId6EPb7ULdgIKYkOC5TsEtaHR/F1vVMq
         ZWng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709026225; x=1709631025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mo91yDl2ymbVTks9COlmiRk05cIm9YtynpF1VS2/Zlw=;
        b=WBI2J6Hw2GkfzW5olGg6L26ujifxTFS4tGz8UMb/zb88NUJoAOhv4orM6rQnG+4QQ3
         r/496vYThPgcBPv8b3mVEU+LAGLEOAIoKr4STKpTGgWyqLwbsMYxAQpWFpHGOVMnm5kE
         MNcFLvJ6IjPrDey5ci9H5y3F4hET/ExWcZHbH9oJyQbc09Pn+is5Axo+oiUFzUuPTUun
         ta8e6T8L/qvXyzF65Dzvdaki/PkpXaNPCPx+JH9/9/FIWBxaJZfJRgrqOe5EEtuIBBRe
         OfoLuKBILeTpVvq+S8X+kGp37BxLgjHhitzNuZoJMs/HAoPfXcsWs2P94GRXVK84ITeE
         6Mig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709026225; x=1709631025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mo91yDl2ymbVTks9COlmiRk05cIm9YtynpF1VS2/Zlw=;
        b=a9XpfpsvuUzb7cX1NEAgKXaz1383//zDAj9nrN/trvn8xfM1/0qEWq3zC+B2iunjPK
         6ia7xjMud3pw0tlVOoSOGPhAX7PLowQZAA5FOZxwr+0d9kB6Yb1SEY/RJtOuiJ/7CUEg
         f93aMHCj9uMwxXrOtZnUrfVyRwN6WJcc2mp/Lo/6XEbIKaLf0D20RyaSSho1QyFGVH5J
         RDpTAiXTZAR5lk49SmxoEJ1qnR/qdNSzT88SAnZK/eB4RAvOzSzfv3zbJZrZXvQ9xjC4
         EjwX2padZHnDqCNbljJtZczubFSyA470i/Ywo4KTjuYXiWeUDimVUzAwWeUfbhEs6UmG
         tLxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWE7a3F9REVepxTpOxgyUMC8hwRFpI9Ohnu7K+Dq6f+Kh7yporBvH51D4KG54+qJdiZrYU6ysCyl/AHe9k5XBZOuPJ2+DjFLg==
X-Gm-Message-State: AOJu0Yz9/p2IbT/bgARmmwmdc/QgXYIqkJet9gscUe2saiALYdG+rOjt
	TxyiK+Pkp9hiKO6yWcMvDk38GIi+bpe7xb09rzBbPhBidzhgpJfQ
X-Google-Smtp-Source: AGHT+IHC3KAhzLIgfD3I+Zghu6WFl19tfTyWqm9PZn8oizPRB+E4YuIhJAICQIjGfqf6h5rEHgX3Eg==
X-Received: by 2002:a05:6512:926:b0:512:d06b:2804 with SMTP id f6-20020a056512092600b00512d06b2804mr5699392lft.33.1709026225111;
        Tue, 27 Feb 2024 01:30:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4026:b0:512:cb07:f4c2 with SMTP id
 br38-20020a056512402600b00512cb07f4c2ls652467lfb.2.-pod-prod-06-eu; Tue, 27
 Feb 2024 01:30:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWj6RyNXh4Nt4veAHM/azX15OSKSh/rfrUWQPO/ve+2VjawYUaLbdtwCnbG41U/+/DcTSZJ8p37JUHvqzzGSkU252Xmt/HSwA1EPQ==
X-Received: by 2002:ac2:4291:0:b0:512:a8a8:487e with SMTP id m17-20020ac24291000000b00512a8a8487emr5351178lfh.40.1709026223061;
        Tue, 27 Feb 2024 01:30:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709026223; cv=none;
        d=google.com; s=arc-20160816;
        b=KPyEgbcAmWG5wzerly1JaQPwDPeQKmLtJh1s1liVekAdMeuPwLb5epXdBDNBce6cC+
         1M1zCQLFrG82PumWmZTKzTYKSBR8A/7AJEbGvv9CVNMFi4QraRI2WyBvKpSuuWeM8rD6
         hlJg/ywXj+fJXzTcBMgHP53AIBPgubEUNA1uYg15aFfry62FXOWYO7ukqzarzQiTO/eQ
         705YBDzOQFjvwojmwe/zDE4pD2F9N+buklM+CSyuEjw5f1OUu+gkhAMQlCuAdubXBvOT
         YxvsS2v2Ia79BjYUtSdzZGGbE/yIKUF34xTnQtxKmFuW3okvI1baLSKoefzt44p6irnE
         5K4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=2tfyNx8Ewzx9RhyM+EFV+xT647ehMQIa9lFPRNlyECQ=;
        fh=dOHsy3mSRCJvTZwWeFaoCuCHq/O8VVJOOHQkFc4Oa7s=;
        b=WSFJboZTktMxDBDecv2udgHiclNstxbgxQCMPV2/XHELp1QuV5B/Fk4pjzMAPPMnXB
         +jHaNROLXdvxPinuS9hZp4cUL4f+HKDch2yoLOjFU4U+ezZo62PJ/2MPEDeNexUAvkjb
         q+HA2wOs13Uc3taISZP8j5gLUQeFgLQs10a9wqwGkwOrv3eoJ5J7WmGqGaNv/XGj5whE
         gqp0ieo7QsIrpKF/sqywswd+CMNAMfvqmQndoMv0cvIOF7YDkADMihOvImCYgvY7c9qt
         y+2EuJpPfx8I+rlRqQhNqBMSE7VAwWn25MCtcZQ+crHucmqZE1Z+aMUen1Q99jnT1JwK
         4qJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id be42-20020a056512252a00b00512f6bc1782si444820lfb.7.2024.02.27.01.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 01:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0702B21EC0;
	Tue, 27 Feb 2024 09:30:22 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B04E513A58;
	Tue, 27 Feb 2024 09:30:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QuGyKq2r3WW8cgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 09:30:21 +0000
Message-ID: <72cc5f0b-90cc-48a8-a026-412fa1186acd@suse.cz>
Date: Tue, 27 Feb 2024 10:30:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 15/36] lib: introduce support for page allocation
 tagging
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
 <20240221194052.927623-16-surenb@google.com>
 <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz>
 <CAJuCfpGZ6W-vjby=hWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpGZ6W-vjby=hWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Score: 0.19
X-Spamd-Result: default: False [0.19 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-0.02)[52.97%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0+Xj01Kk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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



On 2/26/24 18:11, Suren Baghdasaryan wrote:
> On Mon, Feb 26, 2024 at 9:07=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 2/21/24 20:40, Suren Baghdasaryan wrote:
>>> Introduce helper functions to easily instrument page allocators by
>>> storing a pointer to the allocation tag associated with the code that
>>> allocated the page in a page_ext field.
>>>
>>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>>> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
>>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>>
>> The static key usage seems fine now. Even if the page_ext overhead is st=
ill
>> always paid when compiled in, you mention in the cover letter there's a =
plan
>> for boot-time toggle later, so
>=20
> Yes, I already have a simple patch for that to be included in the next
> revision: https://github.com/torvalds/linux/commit/7ca367e80232345f471b77=
b3ea71cf82faf50954

This opt-out logic would require a distro kernel with allocation
profiling compiled-in to ship together with something that modifies
kernel command line to disable it by default, so it's not very
practical. Could the CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT be
turned into having 3 possible choices, where one of them would
initialize mem_profiling_enabled to false?

Or, taking a step back, is it going to be a common usecase to pay the
memory overhead unconditionally, but only enable the profiling later
during runtime? Also what happens if someone would enable and disable it
multiple times during one boot? Would the statistics get all skewed
because some frees would be not accounted while it's disabled?

>>
>> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>=20
> Thanks!
>=20
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/72cc5f0b-90cc-48a8-a026-412fa1186acd%40suse.cz.
