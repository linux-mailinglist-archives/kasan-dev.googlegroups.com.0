Return-Path: <kasan-dev+bncBCKMR55PYIGBBYOA2OXAMGQEJLISOJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 622A885C289
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:24:50 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-410d0660929sf28387975e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 09:24:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708449890; cv=pass;
        d=google.com; s=arc-20160816;
        b=MbwR0rZ67t776NaUNeAtxpLkYPQkw8XD1tJ7m4xrGGfL8dWbSHPa3btgCAFpgDOlik
         DPDlPP3knrjNXg/dc9KNYBvuNyfSOzOi1nAPHCBkKVTswRLIZ6tjORQv6y1bQrfqSr5l
         XbFh+8TGnfSsBg+blIe3cOHeLFjp4je1wwyPcsSsQNJtUi8XKp5+ba6eiNqWtyvS9zkv
         5V/w5b8TXcV4FsLHaDwII+zsrb+utrS3cZcWp2/Y7R10wkcBzu2QtOTWEr5QXXQmi7NB
         jiJflDy0B/ZNNYsMEfC9feRXYAXEJab09z4UjepZw1Hgk2SaSOYZUAZ0VmSu49ACG0T8
         0VcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=g8RpDpSYC4A8GN61tt+fk7zBhp5Hmw70o+htjfAa/Qg=;
        fh=uwgWOd9T/jNj8CSCRQN9IAU/9yJco5ZIFgXw4PBfIc4=;
        b=W6mOD9AvUVn56N+FIas/VM6lkZMrrsqmA3fPzTI5MUrn1/E1f8gJmGFi2MJHOJy8DH
         kdxEvj5crhVr9Xe2ng6HO2r5+003BvgScrR6crQSVoyyEkwUoBTE9CTNH9mVb0nVbaYi
         hSGekQbHIz5n5qsKHLOJiifDjjMLuARjFs3EelUND31Gq5kZeUPG86pf3nnG8GPwWYPj
         hAqtv0AgRH6mhF4EE5dx7ujQbB7cTwsnazA+LKbuOM8MsRg3iPklG+QfyEQLnrGST7Dx
         0mXnmzDQamty6XCN7fPQ+FlJBd5brJBFesKPvQB/2mzVmqLC9k9RosroUS+eiRuF+CBY
         4ndw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708449890; x=1709054690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=g8RpDpSYC4A8GN61tt+fk7zBhp5Hmw70o+htjfAa/Qg=;
        b=qAO1l7aOsLymT06F2KU4wYFcRObHCWTIjzvTgJxkusMw1POYb8Hx+ceQcsebfqltFz
         EUB8JtFm/dd6YJr+INUa/EaARrn7o9GAM5iaGipayXhF5y4M7s7eY/eCERm5HSFgSDR9
         eZ2PLxCDPY3ygdIn4xSg7I9vVvTCMateGjlmA147w386xWkstk41TbaMvQeHuSfybICm
         G9LyNcx0rwjPLLP3KyY59KzB9pz9UD6liNjSxibZUi9FiaxE/NmHC5iTN4Id0hrA2b8B
         rjPWBXQRwgCid3J1Daoz48KvDi+COb9z/+htIv6Fdn4PHzt1pNahekpIBStc5jJU6JiO
         8Xnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708449890; x=1709054690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g8RpDpSYC4A8GN61tt+fk7zBhp5Hmw70o+htjfAa/Qg=;
        b=SbgUDtnbOHVDZadardfCe8WEGuT7udVV/cXbV45JhK6OmUuz4bFBbe7qt5xGSrgUhX
         5MuvNbBS4eUcSCjXh1DUnfJObnOziQ01KQAQG2xKUE8cHiLuGNf7PDa5xQl1WuzCYPk4
         qPO6izfUL/t4q2G9bANyxkDftTFwDmOgHjKJAXOtFfFOVJtvmkvbng9AqGIdOyY04NOT
         w6oBGjvHqLWkBdGeTNMTyIbGGHU++dEjx/PRsxnuYmUMSO5yVO/HsNZgiZl/Fg+QPZYw
         kL9qJDdTM6bawJuuzrv6aQTr8b25/n2mSDO3518563GZxDKqPARmqii1O/b5o8uZnH1G
         4tsg==
X-Forwarded-Encrypted: i=2; AJvYcCUnVAnrDKVWpX20LzJ9Q3kerPXrCSXHPI9YdKiw63XNC96KlP3oVA2CGPEjOkVgWo53RtKhgWyVJNmILH3mMxgJ+prVj2bb4A==
X-Gm-Message-State: AOJu0YzGNlfc0DsesGEu7tHiSPRLJljErw9Aj9aL/wvi+6BfXqvc0MGg
	jDDtLrpMJgtS5xUKROrfMhWupILBpgp59iPkHTQ6HeU9E98ASFzr
X-Google-Smtp-Source: AGHT+IEXzTXB8MP3cpusCjNHlwWc3cihd1JQSd3F3tQZaToabN74Z//o/t3fJZcwidfYXpY0mZQGOg==
X-Received: by 2002:a05:600c:a3a5:b0:411:ec38:fffd with SMTP id hn37-20020a05600ca3a500b00411ec38fffdmr14227039wmb.18.1708449889437;
        Tue, 20 Feb 2024 09:24:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1e:b0:412:3dd2:4cf1 with SMTP id
 j30-20020a05600c1c1e00b004123dd24cf1ls1749356wms.2.-pod-prod-00-eu-canary;
 Tue, 20 Feb 2024 09:24:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQJ7iY9sNEh7E/IUznSIYW0pxEkXTLRfhJ3sS7Aa3LpLwoj1BRld4v5qlR0X6Zz4slsRHvcfE10I3akYeXIFSyMSy/K+mhb0tNtQ==
X-Received: by 2002:a5d:4fd2:0:b0:33d:3896:be55 with SMTP id h18-20020a5d4fd2000000b0033d3896be55mr8006207wrw.5.1708449887236;
        Tue, 20 Feb 2024 09:24:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708449887; cv=none;
        d=google.com; s=arc-20160816;
        b=hFK75ANB3mU9NOtnpZ5/aG9iDlZtPdPbkd8HhK42j5ViiT+N6g4085R38BJpKCk0OS
         yWfupsKb6ErKBFFTZf+KC5skDuKNhCZ1yDcd47T/Qkg7EfOkY/fq15P5B+0EMu9O6WMX
         xEpM5nysRwFdYPORJA8YjbeiGlqD1aC8aUef9FXa3zCJFuz4IBUP5RHKoBAPsl1Ga8F6
         ALYnmTCy8Q3aDB4wVZWmAR8d6srBVTXUYLcfdw5OKL+f8r0DwuqJp8I2XQ43jZrhug9P
         aFYOrOOEZKlzlmAqPPNKu7aBBZNIQh+tSmHc+/jKVfRfOyGVLS3Jim8M3M6gapKvgxck
         4UTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=t4AkBXTli0JY+7cZt6wPmw2DkCGDriEpGC9jORxnoKQ=;
        fh=upQfiW1Lc4n50NXZQ7czm1Dy08GufKWRdtonyBmXd9M=;
        b=F9p05lCOiz0O3UgCtgKFhKzHvPhmlM6DLdFN0A9tKwVI9mduFB/MpaTFtJ0jxJgwb9
         vAgxHDbHuKffHhbLspnafxedfQsRwwL/wRHtyvqOKDFqmI4FyS+ocd9ObIDP3zBW4njr
         sSsG1X/T6EGgUdm2O1/Cq3vXsUzMZZcsYBKEJInjYvSIT+94hDuNuLWW8dtB5VZ42uHg
         ICw3hRnFxqZ05b1KImu+WKu/hKUkI9EaP4xIEeIs1eKVX170C9zYoz6fA1zMtQH6rFlc
         guUooWp0fo1StVYUflif6RlNxL7BC7GSHlvBwdkie3PlWbf89o+2j5n53r232lMrXCie
         czlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";
       dkim=pass header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id g15-20020adfd1ef000000b0033d24322b09si399608wrd.0.2024.02.20.09.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 09:24:47 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A57631F8B4;
	Tue, 20 Feb 2024 17:24:46 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7A510134E4;
	Tue, 20 Feb 2024 17:24:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id A2RRHV7g1GXZYwAAD6G6ig
	(envelope-from <mhocko@suse.com>); Tue, 20 Feb 2024 17:24:46 +0000
Date: Tue, 20 Feb 2024 18:24:41 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>,
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
Message-ID: <ZdTgWb7eNtF4hLw2@tiehlicka>
References: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
 <ZdTSAWwNng9rmKtg@tiehlicka>
 <qnpkravlw4d5zic4djpku6ffghargekkohsolrnus3bvwipa7g@lfbucg3r4zbz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <qnpkravlw4d5zic4djpku6ffghargekkohsolrnus3bvwipa7g@lfbucg3r4zbz>
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.49 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.com:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.00)[34.29%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[google.com,goodmis.org,suse.cz,linux-foundation.org,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.49
X-Rspamd-Queue-Id: A57631F8B4
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="aQPLcI4/";       spf=pass
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

On Tue 20-02-24 12:18:49, Kent Overstreet wrote:
> On Tue, Feb 20, 2024 at 05:23:29PM +0100, Michal Hocko wrote:
> > On Mon 19-02-24 09:17:36, Suren Baghdasaryan wrote:
> > [...]
> > > For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> > > becomes safe and the only risk is to lose this report. If we get cases
> > > with reports missing this data, we can easily change to reserved
> > > memory.
> > 
> > This is not just about missing part of the oom report. This is annoying
> > but not earth shattering. Eating into very small reserves (that might be
> > the only usable memory while the system is struggling in OOM situation)
> > could cause functional problems that would be non trivial to test for.
> > All that for debugging purposes is just lame. If you want to reuse the code
> > for a different purpose then abstract it and allocate the buffer when you
> > can afford that and use preallocated on when in OOM situation.
> > 
> > We have always went extra mile to avoid potentially disruptive
> > operations from the oom handling code and I do not see any good reason
> > to diverge from that principle.
> 
> Michal, I gave you the logic between dedicated reserves and system
> reserves. Please stop repeating these vague what-ifs.

Your argument makes little sense and it seems that it is impossible to
explain that to you. I gave up on discussing this further with you.

Consider NAK to any additional allocation from oom path unless you can
give very _solid_ arguments this is absolutely necessary. "It's gona be
fine and work most of the time" is not a solid argument.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdTgWb7eNtF4hLw2%40tiehlicka.
