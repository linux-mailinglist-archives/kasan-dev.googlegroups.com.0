Return-Path: <kasan-dev+bncBCKMR55PYIGBBCNE2OXAMGQETNEYZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F68C85C125
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 17:23:38 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-410422e8cd1sf22616485e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:23:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708446218; cv=pass;
        d=google.com; s=arc-20160816;
        b=aMp2lzVMZMhDlK1P/9dni81HjPM3xyYq7Vrj8jYNOFzz0HdxQcHAqutc3PZD3153+D
         NQb09RhcqxqJDA+GIT/q7vxOdhqRtBFjgM9/EbBNmR8nGBzHfEi8QTFjOUnAFawJwh+o
         9CMmbuGiSrtjnQD/ceNl6Noa2SHKa92vJYA5oBvXLV9d4CChMUZHuHKKCzx2QWurxsjx
         LIEQV9Io/MJKpQt9OUNX7MMOH6vhHnEJwLa0NO4YFTMuMHLyWD7+k0SHc+iWon4CPfTq
         RZZnrk/t1nUHAj9W1GruuPY6h8ivkLEP/6F9Xnova0yaBFMCbLZ40ouZeAJImwOmbsVi
         fdtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KmikM4jdYOA0UbKJtp3sZ+fIfojvGCYiCqo4tSCx4ig=;
        fh=7ZeqZF4AP8hf4xVtz7cuDmaKCmlX4d7aKJDKV94HfGU=;
        b=kZ9l3v9YqgzltaDw9uVCG+akRMuVnMzqSLWIwtjonkvP+Z9Y22fJQpfxzV0c3284tC
         iQjRT6vkvlLc5DktXmS2x/F3Kmgxq0sMFKqzL8qGSCVvgI9gB/Db6vkM4VXVT/O93LAQ
         a/3QBwhkpnn2jaELI77bMQ3TxEbAaR68dO59Y59L0OlTtfrqiBA2NdES4HS+MB7eoZam
         Btsc3sS0U9UUDq+c/xpxXZf5ePGO7ZGE2DV9hYj3uvKPqYZwsIoCrHhogrQjhIGaz4GO
         3P3j3hrlZfwLTt61nCfF9fMEfrjfI+zu2AN6deGQ8/S2SgZMajRb8b7wUPzeL0994d9/
         Ivbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708446217; x=1709051017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KmikM4jdYOA0UbKJtp3sZ+fIfojvGCYiCqo4tSCx4ig=;
        b=ld6atoOVeI+QIh42PuLM1SsDZYZ0mEDv9W79Vmy2wWE0CoXbJdm9uA3Xy3AS79jTel
         3cvmwmsQtFXQNBzGamvM0652BVAQRttaTAr0ouyuOLSsy13G0yQ1cTknOZg0ultbBF0O
         3FGV2jrO1Og/IznC3WfcDoN20AX4vi5CgSkkylyjgpDUVjscCCfND0peF7Qz3horD85x
         D0j9fMdGQ1ODeZ3WAyFrphieEzozrZfaa6BP+SC+XBrU58/EC7Gj2D82K2wfX0FAEKkK
         EvO+z9QRm/KARAT/gWtKMckPbN0n+8Q7PIJOQO4/wbAnkSvXLlBmIoSKYZNx+cno98zs
         yKpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708446218; x=1709051018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KmikM4jdYOA0UbKJtp3sZ+fIfojvGCYiCqo4tSCx4ig=;
        b=rBxeNsCLjizJRVZ/2r0GIdi6eNF2LjIxDkD+/mqJpuw4zO4RqufWYiREjqlCJJLkLa
         ie+rnR9YxofVS199bpoY32BVqGROnBGEet19QkBjBM9kCAM02NQH27OIwHBh3Mp8lIL7
         mMq+U/ikFyAZddUM3fKylaXMU/gcP8QGVtjRWs7p+35G8/n4/Nc1lHlsTGy278+1eNHM
         Fe9nMLwqFp4Owt+P0aMWUBbTs+Dwt2cP4boKqd7QDnu123mDh8g7e0CUk6xndBt/Oaty
         JHwVLch8bTDeJNwo8DyvyDY4VPVcRisoao4cNMzKMxwca5MpdFemiQ49qwBgPu9sNpJe
         c5Zg==
X-Forwarded-Encrypted: i=2; AJvYcCWqrfRwb4rnlWKJ+h8k6UH8Y9b+NCEX3W8apA0vqxEJQWWJhOtqe8KekovCJ1ahpTNf/WFwTcadvb1Tr3Aw9jDhcN9viJmr7A==
X-Gm-Message-State: AOJu0YzX1VjD7qtl/sXb082EJ+UDYCF+fdbplUJC20VTUVbbiWIU7VDq
	C900zuQIZRbe45HQvalJCDYibH2Hipe8wMUroVbcPdB9SbY1duEm
X-Google-Smtp-Source: AGHT+IEVGtq3j9pbRvoaHb0Eq2VFCmR8Aeaxu02/75C4DYG7YjevZiJ4SyAsoDrJozY4N1hsuYcXHg==
X-Received: by 2002:a7b:c407:0:b0:410:7e1c:e384 with SMTP id k7-20020a7bc407000000b004107e1ce384mr11969536wmi.41.1708446217201;
        Tue, 20 Feb 2024 08:23:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8b:b0:412:6aa4:2131 with SMTP id
 bi11-20020a05600c3d8b00b004126aa42131ls771503wmb.0.-pod-prod-04-eu; Tue, 20
 Feb 2024 08:23:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUC5Qha/slpMbcnKWStyf/6vDQGYTAA8C0iZuZnVIhpcrxcdU5c0NG9Z6DZwQhMMpCKV+wBBpjkiKJNMIq0tBnz5shHZ32ZyaLnlg==
X-Received: by 2002:a05:600c:a386:b0:411:ee70:ed5c with SMTP id hn6-20020a05600ca38600b00411ee70ed5cmr12130168wmb.12.1708446215083;
        Tue, 20 Feb 2024 08:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708446215; cv=none;
        d=google.com; s=arc-20160816;
        b=DEHQqfGZN7Os5OVqAN+9Qn6Nd7E2ngKHclTjEu6GEFK7Orfs9kVzZdTeVriJ8XA3ht
         d3PqEY/TnD0Oegxafh3MiL9t630t2pS4EvwP0c9Yk/zvBwj3cdqBAVWLCD7kK/dv4Xr4
         HPey7e2pAebutuBxFucDYicJ7WqbW/MrvhuxIXeyCNPw/Ds/OkV1gAHshNTMLyDxnPla
         wU1iMNCjt54dljh7bVuGO2e2izUdITkTHZCL0qCNr+DN34nQKVGRNSD0/o1S/H71/g9B
         sURQryZsgJBe0yS1TPF5mkwD2UQVoBJ0jpQcmhw11L04ofbQjo2PQ3zoHG2mSyIcW8wk
         MuDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=h8kDAAJVm9DuuVWWpgF8KUfDBqc/AfjUKVkybEu9ZjA=;
        fh=Irc8DyVFXUpBi1TsipuPTtujWedji5g0RAzplo/y83g=;
        b=SnK+GckJsG8GLM60JN1r/SH/Hnyr13anEZp1hO0kyNceQd1KOBqPHplrdxLZIMAotH
         pa55oWUg2vYe2TNSBbfQ+lCcopInvedlk8HoROLj+ZRJ9u7lXY1F/lirIbl8gKhYbJbH
         777/+aB6rcZvZGpgIOhRur38eRZWaTh3umjsJoup7ChqGPgYc3RaQ5cYaXvDG2uZGbhU
         /MDccSLp9deeKnLPwSf1UT6oCfe1pp5CbERH82b9YMFy3MpNL3DXa4DW6852sUlAd179
         p9oNc50iz+vqYUt6YT/ZOqg2qVoitfoXs8pfLStkqI2mNfhSUmWhVBxagcWADsCLO8JE
         q5pQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id y9-20020a05600c364900b00411fc619abfsi484690wmq.1.2024.02.20.08.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 08:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9D00D1F8B3;
	Tue, 20 Feb 2024 16:23:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 77DA3139D0;
	Tue, 20 Feb 2024 16:23:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Dr6rHAbS1GVrVAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Tue, 20 Feb 2024 16:23:34 +0000
Date: Tue, 20 Feb 2024 17:23:29 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Steven Rostedt <rostedt@goodmis.org>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com,
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com,
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com,
	dvyukov@google.com, shakeelb@google.com, songmuchun@bytedance.com,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <ZdTSAWwNng9rmKtg@tiehlicka>
References: <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
X-Spam-Level: 
X-Spam-Score: 0.70
X-Spamd-Result: default: False [0.70 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-0.00)[16.99%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLibijwhxa4crtso4io181jfzy)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[linux.dev,goodmis.org,suse.cz,linux-foundation.org,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=ZFzfIWnc;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.131 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 19-02-24 09:17:36, Suren Baghdasaryan wrote:
[...]
> For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> becomes safe and the only risk is to lose this report. If we get cases
> with reports missing this data, we can easily change to reserved
> memory.

This is not just about missing part of the oom report. This is annoying
but not earth shattering. Eating into very small reserves (that might be
the only usable memory while the system is struggling in OOM situation)
could cause functional problems that would be non trivial to test for.
All that for debugging purposes is just lame. If you want to reuse the code
for a different purpose then abstract it and allocate the buffer when you
can afford that and use preallocated on when in OOM situation.

We have always went extra mile to avoid potentially disruptive
operations from the oom handling code and I do not see any good reason
to diverge from that principle.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdTSAWwNng9rmKtg%40tiehlicka.
