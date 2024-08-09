Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZPE3C2QMGQE5P2WCWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F92C94D320
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 17:14:46 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5a58399717csf19673a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 08:14:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723216486; cv=pass;
        d=google.com; s=arc-20240605;
        b=kPJU6dcHyMsEKP+iXbs5yF8fOEHXun2PbGsW1k6S0f91r6g/qUy2Q/MSJezFxML8jg
         dd73emtpJEhZkOjzLjXXif2AT2yVeCNFNVq2bv8FglH+vcgC61CRtsdIrINSM3mURh6t
         EDwI/MjT8NRSqHHlfPLwviDtmfIrBu+ws+VPVHGMykBH/QLk4HO4OmZ+wGLk+q5wn6S6
         AKUSAwfhR/yKPCZ875asDrqwXRDokwW14lxxcoBzQejYhoc8knAb0wZQho873y9u+/tk
         8GEsK+efNqZhFy4gvEAmF/NTAMhS9sWN4f7CwxYC45xQwEnKl0v6xhJyZ2iLC/txJHc9
         69UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=rjr6pskdayzQ9ZWrRgwjyEcm8G/79JT473iDBD8vkzI=;
        fh=cgL6QSNmlq96Qdt5tBsKnydZa1OTf0g4m69c+RjZzuU=;
        b=aAHxhq6g+MezUK9vUFNK4J0eM0nVd1iaE2DcGQg9FCYWgwxRiuWfc1Wu5O/wCKn4TC
         tf3/jOAZvoBxiG5qPM0Ea6uWLBjez8/rrULGZuMP1xNn29x9GWoB77GD/npOBgMb8/fu
         NmaJ6ve2zFTlvXiRUSEQN7hIvYbItKpBnQZsnxban9/xxVZeedOlB2ICsGlAwYy9WaEK
         Yede7BHSfbOSnYoze8rfG2GRm87fYDKQxDWJtllvjXWV4evxd+pqmnzzFw8P2uGvVmzC
         sMuCOILtM/Te2wz+kO0wF1qvH3zAq9OUg4GohoUg5raILOczXPxtHzuREe5A+yyUCtjG
         v7uQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jhNNn+pP;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uZQ9GUpp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723216486; x=1723821286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rjr6pskdayzQ9ZWrRgwjyEcm8G/79JT473iDBD8vkzI=;
        b=KabKEaCUziozdkH/toFEw0qb9WDEUuwX2K98R+mga/D53t0evFLVYTpG72AbN0G0lo
         x7q700O+pFO+D4QSyedQ3Veetx3CDHHftu1l3Dn4XvyVUXNuNYviOmgAWx2y+XcEPsoq
         DqIe/A6P7KlToZ/YEOaqnfPETOmNUvkL/NqTI/jzyCWzDQIxNFCLrIJISyNKCB3/VxXV
         QCvVKQp8vI+Aq/8MLi0nn58PullOsJbjro3OqGpiOJJ6doMgnrrJPattL9rbGfANlu0f
         tSI7t0k96uny5hH8vTYd8DwPwz1V6oKh1eJosBM1rHBFnmmm0yRD9f3EYnSZhDwufOBH
         vMmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723216486; x=1723821286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rjr6pskdayzQ9ZWrRgwjyEcm8G/79JT473iDBD8vkzI=;
        b=AH2gEChMEMxCDbCJlggo4S1A7jnmi7w1/yd/cf3sM0Qk1PNpLyQVbsIy8+6DYJ8cIh
         6eUEH4291lMb1Kh8K+jD0Jj8vQgMjiHbcyi3hzL8eAENJhU+j1ja6c3iFMjeEMlhxX8n
         YKASznNJ5n4OGPWPl+WpJfU0oa5QgvYbp1RefLcyOjX6kSpLGRliNljM3n+GuR/XBkE1
         73hHGMZ3GMMF6hLtoo4oBzNM+KfTd2WBJz+GiYwoOitjsj24ZGUHFC7mVoIqkh9k+TJe
         e2QTOyZE5XteqCGqfhaBC/1G5VGfi7l4guezxTq2GNAjRlZ4xLtm3Ep7bBZS3HH4Pacp
         AMYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+lWtuNULigXvzu2bMoZ7APqeoO1/X79Zq/czIyEE5nDIVxicH3XAWAZjB9d3dRub73APU7M2PbOj+i9y+fhCMzgACHnKqng==
X-Gm-Message-State: AOJu0YyOi6ce1m5j0ypJ79EQzotWqjGtSsNBAFLkBA994HDdOFwPGQQu
	t1DWqx/v0qs6tCnpfOguXZre8h78ERvravLlNyIlH1TEsUtZsTuZ
X-Google-Smtp-Source: AGHT+IExYuQtSC1VSLFGbX3NoGZAsERv/r+sxFDLUjjA0gUJotnBpP3yLEgVxei0iF0MH2pxVlQ3Xg==
X-Received: by 2002:a05:6402:26c3:b0:5aa:19b1:ffc7 with SMTP id 4fb4d7f45d1cf-5bbbc4d3f2bmr182504a12.2.1723216485359;
        Fri, 09 Aug 2024 08:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2203:0:b0:2ef:2eec:5052 with SMTP id 38308e7fff4ca-2f19bc583fals10060491fa.1.-pod-prod-03-eu;
 Fri, 09 Aug 2024 08:14:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxfo8kHgLCXDFRdOrfweL7ANcSaUXVCeZuUKUMbSTyYsivHsFMQXmJGHlMIGy0k+3oRSBqfoF2f+s+PFDRU3Vm4kelZ5PTnHMCAw==
X-Received: by 2002:a2e:a542:0:b0:2ef:29d4:3d97 with SMTP id 38308e7fff4ca-2f1a6d02356mr15046031fa.5.1723216483035;
        Fri, 09 Aug 2024 08:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723216482; cv=none;
        d=google.com; s=arc-20160816;
        b=B71i2ELL/eEYmvVefySZOHrqJnZ2t7IeIjE8r0B0g1bivrPTgjlwYZHM+ASzCmx633
         I5Yt53ZI1eAtNDktANRQ7xtdxi4A7ERi+jCZMrmHiRdrh0pK4cz5dox1i8uyQ9ex73rP
         6cPfNZI7NoX5x+GXmFVtw5q/VHe/57Vaw21fgKIacK6NPjDZCFHNu4D9UgLNrkIJ4soE
         XOj0HgYieeZkudy2IB+cqYkaUbTV70E0tYzO7IW5CNIyU8uT+cFWdqrEAxnmac6oxTWa
         uGA2/E6RGxX91WOMlp2YxeSWkH+wkwmu7mKoIooy/F326NPPyB4BN03ZMB2ZyOSMlTfV
         xa2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=jOzonba4zj87CQGADlkc31oIuNesir69pyxpxcebjLU=;
        fh=78+FwmlMTJw8My0wPk+9IlhuAgO9KThK7P/CADctwiA=;
        b=FVGnXEgeO8bOaUMoUT16Pxi+ZHToDCRV1Fz30BeGLSbVzgowPX0rxzs58WMAVfJaB7
         7sF+rKJWfxjL5rDbiJK52bD2N15Kjy8iHXEKaaSfx6lX0EK1B4ewUxzgu6Kgn6L7TLiW
         1RA/WMvJ5X7WWovnH+9J4JvkiH5ivckkU5lXQ263Ni3bcCRNk0+/uSOC92JgN0WhNLjU
         gl2plrWfMWCVYVJDCyG4IC//RdLG1BREpSU+jzk32lRWlkOkST/smfmBo6bkGoc0yP+s
         EbuCHVvKF0RlmnstH3iR+4XYUhpVr0+3ZSOFrVxWcZXUSeXrMa4FxSGzIp1OV3FYJGhJ
         zwVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jhNNn+pP;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uZQ9GUpp;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429c200de83si1144135e9.1.2024.08.09.08.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 08:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3E20E21F7E;
	Fri,  9 Aug 2024 15:14:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EF52C1379A;
	Fri,  9 Aug 2024 15:14:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id AALaOWAytma2IAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 09 Aug 2024 15:14:40 +0000
Message-ID: <e7f58926-80a7-4dcc-9a6a-21c42d664d4a@suse.cz>
Date: Fri, 9 Aug 2024 17:14:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [-next conflict imminent] Re: [PATCH v2 0/7] mm, slub: handle
 pending kfree_rcu() in kmem_cache_destroy()
Content-Language: en-US
To: Jann Horn <jannh@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt
 <rostedt@goodmis.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Mateusz Guzik <mjguzik@gmail.com>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
 <CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.00 / 50.00];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,canb.auug.org.au,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Spamd-Bar: /
X-Rspamd-Queue-Id: 3E20E21F7E
X-Spam-Level: 
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: 0.00
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jhNNn+pP;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=uZQ9GUpp;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/9/24 17:12, Jann Horn wrote:
> On Fri, Aug 9, 2024 at 5:02=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>> On 8/7/24 12:31, Vlastimil Babka wrote:
>> > Also in git:
>> > https://git.kernel.org/vbabka/l/slab-kfree_rcu-destroy-v2r2
>>
>> I've added this to slab/for-next, there will be some conflicts and here'=
s my
>> resulting git show or the merge commit I tried over today's next.
>>
>> It might look a bit different with tomorrow's next as mm will have v7 of=
 the
>> conflicting series from Jann:
>>
>> https://lore.kernel.org/all/1ca6275f-a2fc-4bad-81dc-6257d4f8d750@suse.cz=
/
>>
>> (also I did resolve it in the way I suggested to move Jann's block befor=
e
>> taking slab_mutex() but unless that happens in mm-unstable it would prob=
ably be more
>> correct to keep where he did)
>=20
> Regarding my conflicting patch: Do you want me to send a v8 of that
> one now to move things around in my patch as you suggested? Or should
> we do that in the slab tree after the conflict has been resolved in
> Linus' tree, or something like that?
> I'm not sure which way of doing this would minimize work for maintainers.=
..

I guess it would be easiest to send a -fix to Andrew as it's rather minor
change. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e7f58926-80a7-4dcc-9a6a-21c42d664d4a%40suse.cz.
