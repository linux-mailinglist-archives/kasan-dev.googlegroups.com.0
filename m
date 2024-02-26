Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRWB6KXAMGQES6ZFEUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B4D7867883
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 15:31:36 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d28e15171asf6382721fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 06:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708957895; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZBlDe4Lx6792xCobpWt0Gm56uIGwKdJnJeB01k5out87jY/FwbpOuYgNm6GFEP83j
         jIn7FKmo25KzIa53joIR66CudwONjx8KjOysZAB93X/APS+UKVpmGbmJyCBXB5Y3IhAY
         EmgTY4gQVsPCmxv/p89Mx8HUUVgRL9LDAvfbS0iIYiASmxIz2RnylG6dtB0GE4DtQXK9
         5pPvghKx6CAE3jWxpctBNU2vQ+QokVSA039GjQEvoT6nZ3qPrN/l3apnphmvD0cWZdGa
         PXqDp5DIi9HRFAU6MsMnlXQLR5ILk3HHb1pbQWaCKhY6D+anqozIm1FN9e+QnfcbPry8
         7g2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=bAcR1BV7tLUq+tqCpvofiLCzGhG9F4p379HXBMrxsWw=;
        fh=SJDsaJy6rB+lkqiMpKf8zpr8iIEODtZTzqR6R7XEshc=;
        b=NFgn55yrgTdzwZ++/CWUA0IDwWft/qbIKCwnPcQjhqupIRPy5ltxmmMc2Thx4O0fuF
         SL97wNFuYSQdMWvFDo8sWlf1WZP6SQog0YSzYFWwLpXULuxUkRF0hVIgjx7yeeL/rvWy
         ThZ8VE8fuMpR1RXVBn2Qwpn7CSranU2UvhhkJNrkixZQ5ERpn1syW3KNN+RqklFqwKk0
         TCc3OW3lwiT43/6mIzxj+RqD+1YbtBOe4Kz3OWgjZVi4Fui5+3G56okNzzlIcDboouFO
         /XfS81xTQeK208jqhuFDqxMBI3X74jO+PUJfko0Zn1KB7J6l81VdagXEwzzxzGWNZtkh
         qKKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s3LB6WwA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SFvcoWun;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708957895; x=1709562695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bAcR1BV7tLUq+tqCpvofiLCzGhG9F4p379HXBMrxsWw=;
        b=ppqMOXPUcC/Uinpme803SdQ/ZVuQ9I390jYykK/6McUEsgLyw+kmDEOloqnB3OdUQd
         aba/z57l2cq/41UjF4sNJ7bvAV+Njei/4cD+VUxAYwKadl8D7rS4gAscf0V2nMj92A7+
         VUg+3L5NVt+SUGbmaXmqC2pwuMU/7Sz3XmYapCbJoYlFnK9dXgfs8T40CWVS5kMJudgX
         0l/bTDgCpP/KqNi6HUKottRi9dH9kzIGv4kJY9pPk7SOXP2HJD+W1N5IDQMLhvuuv8Km
         z39oeUb//IslIm7H0OdOwuyvwg6mANp9NKFVcMqg2RP27nNu7yT03myT67sAmUavS5XG
         MBWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708957895; x=1709562695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bAcR1BV7tLUq+tqCpvofiLCzGhG9F4p379HXBMrxsWw=;
        b=BLLt7Z5o29kxx8XPlyBla2Vb5N8w2tXfGfBWjNB+9Qigl3AKCiNDZZ/Q3ndH3t5drw
         3hYnYhoEn/w3lNcvjL2pvDSoaU3g2lFE9adsvPdcXmw+nEWBlCWBKlADgn08LcanqG1Y
         qUyrIrRQfiZWtbmNtrUGhkdlm7SuRRICn5IZJhF8el/90iZaTXPG5kUnEL5OCTdaB23V
         Vbr+CZZ7UIEFNHG/Ceimb3SZyEvIfl2Zq64Aokpul1gKyQBOHwP1gGM3ET/MturtbATp
         BoHyW1hBdfwG+pMAuZjlwtoxCK68qAT6NsTM9LlIon66dr937W2/aeZ5RJX7IowGC4sx
         aLVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6R7bCPxQXjSAbWqJ1u1+prar1YCzJKVXsaLOcQGQUH3O7p8KLkr7yZg4OgURk1W86f51wtNSb2ROnJ5seBeKb6tnauiYjLQ==
X-Gm-Message-State: AOJu0YxxHs9jmvmIkVuGhj41IhcVQPpZMERgkfdNRhT1n2edsCJFRUhj
	MnoHJ9C8mDo19inkD6dbbl7wHa+Aw5gljPLQJN/kLMz/Haj7bJG/
X-Google-Smtp-Source: AGHT+IEDJZUXtfW/HpCr9k4pvbl25rBXcqB6PtjJ307Hu6dLdYBfIIc1ZACB5erLXKY7LDQ0nIxe8A==
X-Received: by 2002:a2e:81c6:0:b0:2d2:2b78:70eb with SMTP id s6-20020a2e81c6000000b002d22b7870ebmr4697348ljg.21.1708957894998;
        Mon, 26 Feb 2024 06:31:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b98b:0:b0:2d2:4324:b5a4 with SMTP id p11-20020a2eb98b000000b002d24324b5a4ls1259646ljp.0.-pod-prod-04-eu;
 Mon, 26 Feb 2024 06:31:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhS86toZDzBlLcGvmHIjQfnJLfm5bUH1dG+0eFzGc5/9AMXg4eIMor16fW9XesrdIhrxTJjt10OwNFJZ2Nwx1EV5gDo8hF9wjqyA==
X-Received: by 2002:ac2:424d:0:b0:512:e3b3:adba with SMTP id m13-20020ac2424d000000b00512e3b3adbamr4499618lfl.62.1708957893002;
        Mon, 26 Feb 2024 06:31:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708957892; cv=none;
        d=google.com; s=arc-20160816;
        b=Hox3NshKKwcqD280w/njKpMflGZ4vajngp1vUMpdOtJVyJAKmLRAkyIVBTr3Cx65j2
         D8iglGHicRZcamr/W5+Z2D20zLyKQZk7AqlVN0c17Cl7Xx3FgVeZiviHwBEFhOeoHAx2
         ZG6xzfdevSPUWt9tR37/7xo0Oy1YYUEIyF2FcTGKUoWFb2NE2u2lHbdvr+tzDHLhAunO
         de05d2o3+PA3FeF6liaU3rO0a0OgZM747122rq1FEwjgYVbCBlBZM4QWSMSj7fbQNByy
         99GSQJ8YNew+PEP2hd5Glh/KgqolMvuwvTsuf+6upSR9CMA+CWG7w2gzHJLziBE6spO2
         20xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=W4akfkc1Kw2e9YyWEpsf9c0Y76JydMXyZR2TAfFVmJg=;
        fh=URVDntxmVf4YNwYHYeoYQFtiJToMDPgJfmfSY73A4X4=;
        b=EY0by37HQQBocmS4mVZvB+ojce5pp6OUAl1sYUwUgEFnESbWLfTAQFQPlSqd6BYTOp
         T2EUegNetouy4eygF9O+gguYUEgAcYL8NA+7d92selGffQlKt2100aXGBesgexbms4cK
         8oUtg+4yxKipuZ4BMzDSarmn266LM59aIYcN8lhvd5isUTKhZykfITmkNQCkplkMmN4U
         Zf3KW6hKl8DDYkvPanT1jE1ibtsgScJ+zd+NcJOjRVzez3iBSHWt3NAdWnpMkcZPS1pq
         ilWNvpHgC0kjwcXvKEgJkZS1K1HXweXJcqaCQkP6MeEDmlhSduYNCby43t1iL6k4fR6G
         8rWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s3LB6WwA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SFvcoWun;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id o19-20020ac24bd3000000b00512f71b7c0bsi316456lfq.12.2024.02.26.06.31.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 06:31:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 452E4224F2;
	Mon, 26 Feb 2024 14:31:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9FCE813A58;
	Mon, 26 Feb 2024 14:31:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id T+5WJsGg3GV9bwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 14:31:29 +0000
Message-ID: <d8a7ed49-f7d1-44bf-b0e5-64969e816057@suse.cz>
Date: Mon, 26 Feb 2024 15:31:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
To: Suren Baghdasaryan <surenb@google.com>,
 Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
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
 <20240221194052.927623-4-surenb@google.com>
 <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
 <CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y+jmUpB02jznkEySpd4rzvw@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y+jmUpB02jznkEySpd4rzvw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Score: 0.06
X-Spamd-Result: default: False [0.06 / 50.00];
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
	 BAYES_HAM(-0.15)[68.94%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-0.998];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[chromium.org:email,soleen.com:email,suse.cz:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=s3LB6WwA;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=SFvcoWun;       dkim=neutral
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

On 2/24/24 03:02, Suren Baghdasaryan wrote:
> On Wed, Feb 21, 2024 at 1:16=E2=80=AFPM Pasha Tatashin
> <pasha.tatashin@soleen.com> wrote:
>>
>> On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@googl=
e.com> wrote:
>> >
>> > From: Kent Overstreet <kent.overstreet@linux.dev>
>> >
>> > It seems we need to be more forceful with the compiler on this one.
>> > This is done for performance reasons only.
>> >
>> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> > Reviewed-by: Kees Cook <keescook@chromium.org>
>> > ---
>> >  mm/slub.c | 2 +-
>> >  1 file changed, 1 insertion(+), 1 deletion(-)
>> >
>> > diff --git a/mm/slub.c b/mm/slub.c
>> > index 2ef88bbf56a3..d31b03a8d9d5 100644
>> > --- a/mm/slub.c
>> > +++ b/mm/slub.c
>> > @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, void *=
x, bool init)
>> >         return !kasan_slab_free(s, x, init);
>> >  }
>> >
>> > -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>> > +static __always_inline bool slab_free_freelist_hook(struct kmem_cache=
 *s,
>>
>> __fastpath_inline seems to me more appropriate here. It prioritizes
>> memory vs performance.
>=20
> Hmm. AFAIKT this function is used only in one place and we do not add
> any additional users, so I don't think changing to __fastpath_inline
> here would gain us anything.

It would have been more future-proof and self-documenting. But I don't insi=
st.

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

>>
>> >                                            void **head, void **tail,
>> >                                            int *cnt)
>> >  {
>> > --
>> > 2.44.0.rc0.258.g7320e95886-goog
>> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d8a7ed49-f7d1-44bf-b0e5-64969e816057%40suse.cz.
