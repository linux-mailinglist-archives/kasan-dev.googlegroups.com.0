Return-Path: <kasan-dev+bncBC7OD3FKWUERBAG32GXQMGQEUPXXGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 197F987D08F
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 16:47:15 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5a20d31ea8fsf2066799eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 08:47:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710517633; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwuQeOPx+mkGd96zo6v4nwZNO2yKpPwRuL7LpJkW+7zlXbTYY7DJME7LV7uj7oxAyc
         m1V1fj+lzu3/jFr9LAPVgmhwnMyg4LRtPRhkkqITpMh/RxpscYOV6RMfhHm39wizmhzP
         KZHHngSQqYOvp1uKjq0hB2CClFrlcJm9/LJUyKOKznWpsX492efofpw4UocwUsO9GDGk
         VpaNbd3YT8gKs4CbvNpZHR+esGqSN2D3rYiVZRQeVwV4/7A9nsWXivwDQ/wVPc/hMo2/
         JxGaqhO3UrvBnSV7X+gbOVsLt2K69joqkj1Q53IT1PJDJfQqtI49pjVApoE1oUTtuwio
         cz3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Jb2kTzutgqstP4vMUkyFPaAAKsdvSUTNYY3I4st5Ojc=;
        fh=IzZmslqF4bKTG8A7+duyYaKvXMPDItcpaNtNHkkwcws=;
        b=LEWiQqzONtexBw7/vTqJY73P0fAEVBoRDxECEOkAqBFztTFtxv9+OSn+jqTzoQwyoL
         RX3tYsKDKWO4F/2rKnqr/yBUyqlD07MSHTG9VlJH03SZ+tEycXO3H6CfS5XEmoNE8NXg
         OO4VI1ZXPSMCLqPH4ZyZ9HHbKvRwHQCPpELEA9JQujQ+8L8vNO6aNFNhekWitpN0G4aR
         gXwWpYiv55v6HprZd5IOIl1PoxoBnOkLpnBHES9umenciFMkkE6f+Mxgce0lIhRcYGzH
         a6sfm+7gW9yiDaTrKrNbMJkXzIoKC1eebucGuEjS7UACfE2KSXHEvkl9vXYUlpikiiJV
         fIEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nM9HEKdL;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710517633; x=1711122433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Jb2kTzutgqstP4vMUkyFPaAAKsdvSUTNYY3I4st5Ojc=;
        b=kkxFhh3jWtA+lKpewEaQXUtplr0YHoZGSTYkMJcbciOYN2dlD9+Ky4hDoHPedbRBU/
         k9SP+A3aWlWPl5RK49P+/QhYDDeLRmcmv22qUmUJzQl3sB1HCYx2COQ2GSGtS3mJ06SJ
         grtcyiFzVqbOZ7jr4a3SlsYYNzUyLe/2PGDh9k5X/Abrs4yjVQ1R1jFXkIo/afSnTaNS
         Qiro1vvaOR7W8xFGJnEURPTQdfylIdDObfWdTh7vuZDzIx+0qBrJFrqFVRrYJQrB2leG
         smiAo4HmtnsAiqYgov8FDPtuuWzpK6KvrWJb3lvqyL88DZkPk7dGdxu5rAfTU+t1HEjB
         lgdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710517633; x=1711122433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jb2kTzutgqstP4vMUkyFPaAAKsdvSUTNYY3I4st5Ojc=;
        b=jHP/dIZOLtJDUaNCa0J54RJohjZapshBhDv8svUdMwuY6JotJoiXMsfiiNGBZJi/7c
         Z4JWKeVCGg2+tOQGwfpUGFNviQsRiKlSp+FFfUYLan4iol+puPlOV333yj+dG+Jedf1V
         wsbhpurwdCwaq4aTrzd6LlifeBtJD1OI3mEIbc+ELeKGYMh6PqC5UGrbJmGEFeBlPi8h
         Ab/c3ZxvekiEt6umRQrKZMT85o6YLxOhM02w5GP2plBrwGW1GrD8MRHCTO3PPWe/URmS
         ywXM6aB+/UTxMqWXiv58mXiiiq5TKAxv114mtRE3rjVZhdtHY1QgoWc5bHi8ZPUT3be0
         u2Ug==
X-Forwarded-Encrypted: i=2; AJvYcCVT2YNf/5nmdIYBBmxtxT8GznsBpVKPR5m9q/JB+8eoOCkmLL+uMhjKCRvGftGpN40WnZ4uSN5ZZ6SFq3VdPy0hxk9KJ0fZPg==
X-Gm-Message-State: AOJu0YxxxxH/MwMjKpesoCvtpaBTAw4xx5h8O8z2mRau1DriBB5PSWXA
	jicqAIGArxJKOjv/xFn1MtfNqLg2E7LsW6w14XH1wsolUCbTOUDM
X-Google-Smtp-Source: AGHT+IG4NtETkpwfFXQmLOIEkt9j3fs7cTmAijPpTnHV1RWW2dFJD69VSVxTXXYclVSUAGwV1TOvng==
X-Received: by 2002:a05:6871:14e:b0:222:9076:45d7 with SMTP id z14-20020a056871014e00b00222907645d7mr1419377oab.41.1710517633055;
        Fri, 15 Mar 2024 08:47:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:28f:b0:222:7193:f2fd with SMTP id
 i15-20020a056871028f00b002227193f2fdls1680801oae.0.-pod-prod-07-us; Fri, 15
 Mar 2024 08:47:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSViWCognwYa7DkyOuuThE59z9lPi/B+nQzjyl/j+cFbPXAhvzBK5b+WOCnYHlQWk1ZxmXx783qIxWSmdPNfj3wSq4wLAtFmNyqQ==
X-Received: by 2002:a05:6870:808d:b0:220:87b2:c13a with SMTP id q13-20020a056870808d00b0022087b2c13amr5620989oab.26.1710517631954;
        Fri, 15 Mar 2024 08:47:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710517631; cv=none;
        d=google.com; s=arc-20160816;
        b=tNAy0UrfaqooawIjvp0CBQrf8j2TRm0/IrPuLQ2nQs3f5fCuztMucVYDPFa8+1oufU
         mKZVvc/EwJ9JlIoBndKr9LS09ak5eX5P8Kp6Tq8XmzAkfuJ8uH0/PQEo7w7MYUqizfNX
         nfOy8Oi4FD05lQmkBIqK5zeSHag5JUEtE+5o5zPcz3NWyW0I1otYtHgxz6g2LsaK3vGa
         9KqXCeu/qyuw5rra3Mv3Ke+wBnZF+xt2dTIgYTPyxn/rOUSl+DLbUDPDEqFWzx4SC1QU
         eNhMzol1hJLJugm2f75Jb10+35aydT04WNxpHluUgfnLlaPp+yxWlw82lltvSUfKvsuE
         /KbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5hTYJR/EPYVQveJbg5FctPr1PKFKWOQ5oCn+BSWzHW0=;
        fh=RR50oXNnzDxJhK5w06x+KBsABrwpK+zpM+diuthaaf0=;
        b=UYYTfRd3TYmUNDR3EUx4rHpriUseANk2KxXx+DojasyPUlhSCWfwu+rOyTB8wWXvhV
         ZJ9YS4IqeKQQcctWfHAh2gVBIUPJ4Ks7wM94k7xIFjRLzAHPsm/0W71CETf0RkNTb34X
         D2UL1IVgdra7WJlr3r4qXWOjps57ELXmwPZyMIpL1AywVA5lZTxO1Rp0DHgt5ZtbvBcD
         VoYo9cg7iaicscLwAj0ZM3WlqmeCy8ZOOSgby0bqUk3RRYwNLXfuCgcKvgFYftThiVKl
         Le1cMEDTm7h/EvbeBv0UXk8CTAezi+msi3QrH8y5wxWAt/k33PWEjIqzYpJ9mD5YNR/B
         UEzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nM9HEKdL;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id gr23-20020a056870aa9700b00221bb59c450si718545oab.5.2024.03.15.08.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Mar 2024 08:47:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-60a057b6601so22239717b3.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Mar 2024 08:47:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRJGEkfXusS8bcDJJxiwNc8AWAH3OPvj/6MnNF4/16TgTh7S7VPTcQqIxPNH40HS0X+dmD9nXXfVaiGDAW6lMEUvpcdLpiJpLzgA==
X-Received: by 2002:a25:ad5f:0:b0:dc7:4f61:5723 with SMTP id
 l31-20020a25ad5f000000b00dc74f615723mr4966380ybe.39.1710517631010; Fri, 15
 Mar 2024 08:47:11 -0700 (PDT)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-15-surenb@google.com>
 <ZfRaBJ8nq57TAG6L@casper.infradead.org>
In-Reply-To: <ZfRaBJ8nq57TAG6L@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Mar 2024 08:47:00 -0700
Message-ID: <CAJuCfpEpMwfEgrsMALqpzH=3FL0WxrXY1bRkvezMdCw2BAtQRg@mail.gmail.com>
Subject: Re: [PATCH v5 14/37] lib: introduce support for page allocation tagging
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nM9HEKdL;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Fri, Mar 15, 2024 at 7:24=E2=80=AFAM Matthew Wilcox <willy@infradead.org=
> wrote:
>
> On Wed, Mar 06, 2024 at 10:24:12AM -0800, Suren Baghdasaryan wrote:
> > +static inline void pgalloc_tag_add(struct page *page, struct task_stru=
ct *task,
> > +                                unsigned int order)
>
> If you make this "unsigned int nr" instead of order, (a) it won't look
> completely insane (what does adding an order even mean?) and (b) you
> can reuse it from the __free_pages path.

Sounds good to me.

>
> > @@ -1101,6 +1102,7 @@ __always_inline bool free_pages_prepare(struct pa=
ge *page,
> >               /* Do not let hwpoison pages hit pcplists/buddy */
> >               reset_page_owner(page, order);
> >               page_table_check_free(page, order);
> > +             pgalloc_tag_sub(page, order);
>
> Obviously you'll need to make sure all the callers now pass in 1 <<
> order instead of just order.

Ack.

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEpMwfEgrsMALqpzH%3D3FL0WxrXY1bRkvezMdCw2BAtQRg%40mail.gmai=
l.com.
