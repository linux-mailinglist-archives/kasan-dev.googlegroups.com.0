Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNEO4GVQMGQEJ7IKVWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D12B080EAA2
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 12:42:45 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dbcc464a1cdsf19610276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 03:42:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702381364; cv=pass;
        d=google.com; s=arc-20160816;
        b=TaWSF+3CoMsRhsA3o5gJPvdEYg8E5GB4pB5GW75iXei7irYvAEviGYF4KFWc9AQIyy
         k9aXiLvMivQVajcF+Tu5wlDk0qJs31/CXt1Aw7pt0siPaaI4n4gbtx5SGlgTJk7bnmu8
         Du4/bTy7iAPYEUfFlA+KhHealOhXVby8oV83ExF7JtGGHdfjE8L6EqnAPWnD3xsgjCGg
         mOnvOn0GrOuD51gzrGw82vRI+sbxTxSduFHktOXcBH4y1hYp8PF5RH9a13DAgXV/hkb/
         bGBlt9lyQtMeenRAdeaushMD19E/6J/NN8zT75yIKYJMYigg0xv26aVfHxV/SdQkG4FT
         IONA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=3AxgVRFHKPXT4XF6pG/409lDAf/cf5yMtmKVd8HW7pU=;
        fh=CExjVUaK55C3nA7ZEh+wz8l2NJon2WwLoXSLRnktXc0=;
        b=xiqbm1N9sAwyZdq2q7LzWnII1TYrCuYEhOAd1tpRGjkwZTlAKCGQ/b/B3Ik5WcGZ+A
         kHOIUpqjK8AxQDv9kSwxnpHPW7eEO85rruAN4BpPnH/nViK28zV6H7OP8EMVtImIMzwF
         TaT7akBFUbe7f+Zhh2wcpeqN4jaBmPmLgjJ7+yxyYJNhj50HKy9AYGfR/KiG5G1tWDUC
         AXIanOs33Yve5GG/yYy3pmHOgEnN0yTAiuR75QZxJqnC6qxdQZN4+F9uys+iQ8PgW8vr
         2HNh0QFn653m39rAnTtaUuqiqoHc0t4WZgVkTcyYvLx0zYQROV2GdmvpdCNwWnKKSnrw
         fyyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F0XdSCEx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F0XdSCEx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="gX/Xrx7W";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702381364; x=1702986164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3AxgVRFHKPXT4XF6pG/409lDAf/cf5yMtmKVd8HW7pU=;
        b=LMl5WE8G3zkdHEqu2Ao4+L44koNLnRkZLx39TzP7oK7WjSwL4ElQbb4xOMQvBCmDXu
         WBgLoopG6cr6ECdQQHvQVLLmYqCXbzEu5d+UMcQA8s0CXPPwAOsnyNAc4QTKQ+cZ9MlW
         8mqp49kHgucIg/3pesme/9GSXO6Znx7ZyfJA28Y1Vaq0EBvzJ+OGMhTBdoeYHujWXNux
         +gDUCbfIGtJH6W29kX+Fm/W0aADLeEmdtOluRcoXBK/2E4PTjRxPR2AgSdLAFljaMzCZ
         QXHn8V+DoY9NuJundHg0XrXZYGuY7xbCHUm2JJ9UJdG62uZx8QLh77m5Vg7CesIyVnU6
         pJDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702381364; x=1702986164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3AxgVRFHKPXT4XF6pG/409lDAf/cf5yMtmKVd8HW7pU=;
        b=JC7SYAe4RYRpgN1DvK/m8Rgwwpz7g2uOhtNjltpzRNqLAR5fQ++EoF6ZPpgMJDtKEU
         vWL6XGiFsTuKYxcJav7vS97Nh3iWuzoxDKqtoSRFE/UpaVWcEYzqDLbSp+SDyJaosnWW
         /E2wvi6kX1y9n6hAvZG0co1XMLIn0s/5m0qBcsFWpG0tAebuY2wRHUWWanCjWdKmivqw
         IOmah5Uo14+BJEWzk1DGWUcnS3lhYHaz6qNg2m36r7asTBLm5W5TQO1bobppIKpwzZFa
         +sX1lEUqHTYRMBEyef7dGsA5b6JKEhdURU+gfj7Wbu1s1eLunGQ29Rq+fRjRN8UbPeLo
         FUCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQHHHeD21MojT6NhNoQMnrKnyzarAB8OopFtO9wVjKA8GRIb9t
	ToKh0SpbgrjHrmVb3wIr7QM=
X-Google-Smtp-Source: AGHT+IEqso9Cbd0HO+YHEWh3HNBQha0SpGbEUFndbCcUuakGzu3f6YQw/ZCzLNTbgyCq8zgOdE5BhQ==
X-Received: by 2002:a25:c70a:0:b0:db7:dacf:6228 with SMTP id w10-20020a25c70a000000b00db7dacf6228mr3874432ybe.122.1702381364294;
        Tue, 12 Dec 2023 03:42:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bec6:0:b0:67a:a15d:e966 with SMTP id f6-20020a0cbec6000000b0067aa15de966ls67874qvj.1.-pod-prod-05-us;
 Tue, 12 Dec 2023 03:42:43 -0800 (PST)
X-Received: by 2002:a05:6122:a04:b0:4b2:c554:ef01 with SMTP id 4-20020a0561220a0400b004b2c554ef01mr4424079vkn.19.1702381363478;
        Tue, 12 Dec 2023 03:42:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702381363; cv=none;
        d=google.com; s=arc-20160816;
        b=Lyjyo3Z1jDhqgYi1fUGphyObxhNWePWEG3ye7tOm94qTdrQAhGKs3xrYJIY+ZFLaV5
         Z6FF5PcrImgUpc+uPhPHsKGd+m0XlA62FK6RTdi9D+X1XsAR24USoaXed70SSqrq4xSz
         CPKDQUAqmb2NsAoo9g8Z01Vo26+5qdm5eaJcvJRZ/X4t0RmDhhfJc+o++Onuz32kmcYw
         9XqLY065H/ss28+871It3y77OCYy9O7aY0mworjL1FYof85GPhoK9lfHVK69/qX7S7C3
         DU38xOBrRzDHdZdBMUsRuTjA2VRKCQAnt+JdVm8txZ3dXhMfw7tzZF5d08YA3SKOUtgz
         wleg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=r8rQdTbhdfN1Wpyhb5CblYIrwW052Y/FkuDWvW+nn5c=;
        fh=CExjVUaK55C3nA7ZEh+wz8l2NJon2WwLoXSLRnktXc0=;
        b=wS8BPzyIjoNdcU5UrVxgYIe3OBlE8QsNuJ75lt+IeRFfi80BbTX8j6kztcqKRWZTbJ
         CfctjxNWWmyaLz7OiIyyJwhuRQE7YyAOtiurlboXid6IAticPheizzLkGs9eDQoX0pmt
         bA/sHLeF3PhlE0DYXKtIBkhwqYRpV+C6ZoUmE+qIwLAtyevU5m1zh0Cv7ZuBKGvVGOdw
         wr6oeJJMqaEqxRl10gfkJoOePzvI7QpxG3HXJAvayzIidy9sQcndKFYjdybc9/6NGYmM
         65aef+23WqVNmjrCWNs7pd6euSNE4jdu7cvZ2+Q15pGu2ikdMUoZSZegIGWqmN5Xpx5d
         Iu9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F0XdSCEx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=F0XdSCEx;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="gX/Xrx7W";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id bq6-20020a056122230600b004abd0f58a5esi1127710vkb.2.2023.12.12.03.42.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 03:42:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6E5891F381;
	Tue, 12 Dec 2023 11:42:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4D17E13725;
	Tue, 12 Dec 2023 11:42:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hcdiEjFHeGXqPAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 12 Dec 2023 11:42:41 +0000
Message-ID: <fec2561d-42fb-dd47-6e8f-3b55aaf39d85@suse.cz>
Date: Tue, 12 Dec 2023 12:42:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
To: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>
Cc: Chengming Zhou <chengming.zhou@linux.dev>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
 <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
 <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz>
 <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
 <CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw@mail.gmail.com>
 <CA+fCnZfhqQ+n0SsZU0RKEov3CkwTNJXM7JTMxtkrODmbJPskDQ@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CA+fCnZfhqQ+n0SsZU0RKEov3CkwTNJXM7JTMxtkrODmbJPskDQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: 1.39
X-Spam-Level: *****
X-Spamd-Bar: +++++
X-Rspamd-Server: rspamd2
X-Spamd-Result: default: False [5.79 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 R_RATELIMIT(0.00)[to_ip_from(RLhc4kaujr6ihojcnjq7c1jwbi)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FREEMAIL_TO(0.00)[gmail.com,google.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[16.11%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[15];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,linux.com,kernel.org,google.com,lge.com,linux-foundation.org,gmail.com,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Spam-Score: 5.79
X-Rspamd-Queue-Id: 6E5891F381
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=F0XdSCEx;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=F0XdSCEx;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b="gX/Xrx7W";
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/11/23 23:11, Andrey Konovalov wrote:
> On Wed, Dec 6, 2023 at 3:45=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
>>
>> The is_kfence_address() implementation tolerates tagged addresses,
>> i.e. if it receives a tagged non-kfence address, it will never return
>> true.

So just to be sure, it can't happen that a genuine kfence address would the=
n
become KASAN tagged and handed out, and thus when tested by
is_kfence_address() it would be a false negative?

>> The KASAN_HW_TAGS patches and KFENCE patches were in development
>> concurrently, and at the time there was some conflict resolution that
>> happened when both were merged. The
>> is_kfence_address(kasan_reset_tag(..)) initially came from [1] but was
>> squashed into 2b8305260fb.
>>
>> [1] https://lore.kernel.org/all/9dc196006921b191d25d10f6e611316db7da2efc=
.1611946152.git.andreyknvl@google.com/
>>
>> Andrey, do you recall what issue you encountered that needed kasan_reset=
_tag()?
>=20
> I don't remember at this point, but this could have been just a safety me=
asure.
>=20
> If is_kfence_address tolerates tagged addresses, we should be able to
> drop these kasan_reset_tag calls.

Will drop it once the above is confirmed. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fec2561d-42fb-dd47-6e8f-3b55aaf39d85%40suse.cz.
