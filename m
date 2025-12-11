Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUUM5PEQMGQEEGGLGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 361E2CB601A
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 14:25:41 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-7c240728e2asf77505b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 05:25:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765459539; cv=pass;
        d=google.com; s=arc-20240605;
        b=XyzPse7thlUAJ5KAbze4RXQMXjtQS78qLToDukhSDqw5GC4n+mCx9KAWTp5cYRPX7Q
         ZYpZ/dsm+sYTqA/kzU1fE7IfQb2cOe9C+unTT+UdiVwNObMWEfRDdrQ6vFf64qYHc5It
         KaKkDpbIwfDByjQlgIH1vT7xK1PEOrV2Da19qx/aNU/T5r9BNJiSYNn0yCDJ5A1a3Mh3
         n85VCbw0DkB/eM3OY6k59SDhLjCALv/2eG/vhZqnLq8yCYnDZzWE30XvOuThFQrOv97N
         +uPcz/2y5fRcbSaXsvEFSzB2FHcqSbqMzi5U6x4VXj4SZK/Wr9tayAUlzf2AB1QzkbV3
         KEBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xSYGT9XxjS0x+34f+UHZ2bu/hYvca6ChDQTNN/cP19w=;
        fh=ibc+ZNH4u5cFAh2ZlmxE8lxtyP5nwty1DPHAYSNEymw=;
        b=YmSJayeGxIZYH1F20g7oThZLMmBWVyiU7FRDPvcsFyZ/ATLjZuQY0ydyoYYlnb/iSa
         7YGEMWQmcURLSXz9Osv2d7OWOiq5v3t7NBVbJcHSKJAWSXJQZ0KsaNV7tmtg0eVUKXKd
         5HkLoHTE6f7VUW7fvHIqs3S3gD/3UDb4oP0xPIuWc8KAgKNqTnb45T215IWdfH9/3JU4
         ILobYo4P0Ju3Xa1zW6H9ASJy8hXnd9ltAzKRqJ6EoEbYbjIwNs+GcRyliLAsVciRTfLh
         j67jSJNiC8nlPULGAX/kvCOeHrySFs3ERU0npu8WA8afOwe9jcC21t1KL23GAFJVkxda
         CFKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jiAuuNaN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765459539; x=1766064339; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xSYGT9XxjS0x+34f+UHZ2bu/hYvca6ChDQTNN/cP19w=;
        b=OB2a3j+zw241qQXgqZ3Vbe24pthAOIIjzjC5tYRJ/R/PC+ZBm1Zfu5E+mhQ9OHMJb/
         3fAVFPlkxWe99Ebeh3Zv4vpXX9qhNY6kYFG28BIYxN9DtQqFPX/5FNP8J5XrUWww4zn5
         DbyQG/9SmyXOJkq6gRFQ+n7CC4LG4H+o9TjvUznUUD7yf/hDrbk5vqbz/rerNSnPadCp
         R/RoJ3cx6SOMOMdHpgIMcjhFtTHS6tecnDkzmhFLA58nPN9vQ2V7zNequX8wHnPh3xav
         xNn/fA+jeba+7WK0pd7Y2JUvXA3BfsL9wlkefGTTeKLGXlefef0zp63rP5VamCJOu1uR
         UqUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765459539; x=1766064339;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xSYGT9XxjS0x+34f+UHZ2bu/hYvca6ChDQTNN/cP19w=;
        b=hxxtuSt32hASPdo/woO0GmqUX+z4orpw85/1a8NF3tX52EfWW3fgV8VFXBlF/JdYo1
         X9d6gpBR0CISRn4qXeoCHFLbKMDptj6lV7JtEf2k66MJF/iVuA+NL266WPE39it4AkKJ
         JaYAna5n3DQn67y5VhEFhoJWPy60E8xKqoD7b8AYyxVluKYpjlG+slhpLaXBmRrLIss5
         /hPKNfllLxXCvfmk0kz24qJJdJhTZVsqrNDuEuB+YpKSUeNkezGhWyCDpQ8fJYqgtKmA
         kZDaoOLtbI62nzfsJ0LiGJnmfBSTklJ/QcHUJ/6atZA06Gquouc9keTgYZL0RNYb08iQ
         MsJg==
X-Forwarded-Encrypted: i=2; AJvYcCXgQBpXI1z1S8ByT2kE0BtGZvMB9Xr5WyUedD8R8rUUz109VTS55o3jmJW4+w3xoBzlH3WXfw==@lfdr.de
X-Gm-Message-State: AOJu0Yz/lKrTlIsIUfaFEgxwTUseo4fu8Hbno9mIE1IKwab+2hIlPtVL
	zRbdf+vD0hmxFNfMokjVQ6QD86GGDHNDHm6nhegUUPUdeE/eQRwp/LkW
X-Google-Smtp-Source: AGHT+IFR4qKnvcLPydALU4XFEVrTiMS2VLO9Zz0rSXbfHr56h88r4VnaXf34kHRk+s4HgCncX4vMuw==
X-Received: by 2002:a05:6a00:847:b0:7e8:4398:b35a with SMTP id d2e1a72fcca58-7f22ee59d21mr5927954b3a.45.1765459539200;
        Thu, 11 Dec 2025 05:25:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbc1nCu+CyDgMUYqoPXsPV3iV7df4UCy94hCScbPQpoKg=="
Received: by 2002:a05:6a00:4884:b0:7ac:a138:8068 with SMTP id
 d2e1a72fcca58-7f4dc686dffls592098b3a.2.-pod-prod-02-us; Thu, 11 Dec 2025
 05:25:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7UCy1foDowzVhNgNSjN+MiiNw6j9nLaI8hm0Ps1xwMB2BPeBVfZPt05wZTlUczMSSRajltKMfAOo=@googlegroups.com
X-Received: by 2002:a05:6a00:2d0d:b0:7e8:4398:b36f with SMTP id d2e1a72fcca58-7f22fde1f5amr5498792b3a.66.1765459537544;
        Thu, 11 Dec 2025 05:25:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765459537; cv=none;
        d=google.com; s=arc-20240605;
        b=BusWdllqRlbwhb+PiN+VG7QqfsfGOmhVa1XGG/DYWExazXIE6rYXEgATruthvL/CZj
         nUqy6Un+WoTb1ryCmJYKSUrWbmbyryxzgQR4moB9DcUJJbepXRJ4D3cAbj3KoXrH8hix
         /BArTHl537/9MR93shCcorDPzY+ziVDivU3aZb+unlpICgH5y872XU8sy8aS2qLB2+Re
         0XnXUp81/fJs+wxGLgHoOWEB03AdSQkxevzZuV5kfMxNtG9tCevaVf6RpfHAKumbvbba
         zySJOcXZKMY1whGa2lMLqvnhQsChD+6U6UVMqbT9Bdx4VEbhKG6wd6I1od018vxndX9i
         qSVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bWA/kjxAjN+uRNvgRsuZ3C4JKMpyTL0y62dCZ1FivCw=;
        fh=obYVqd1ebF7zaqfdk4dqYAwzihVLX5tif6zcj3GEIOI=;
        b=NSXIdfZ5yfkKY9WsbMgbjF+fRhfZ47FoAsbqYPnXpU/QinqNvC4YOjekU5aWcCZ9Xa
         s0N2hPga+egkWsVR7BJXY9n6+9D08kbdYF9Clhr+g65U2JzhqtzDP85OEae8AohxIx0+
         ErCMrHqAJaovQLB5g78UsMjO/RBOMuP0GAIfbCsGZ4Lb+jx7j7CyUVW3cxRIv+ROt/cx
         mmDsVbYLEloAIyRm7ZwAnYgwCv+5nTJXIEdwzA9+gzIpht3uSStjnlFLRrM1FxwZ0Tob
         Rcz95Ca/n6u+dQ2JFaS6IAUuwT6AqoG/mwNQjRjsodVNcXpzuxR7xu4tmjihFngB0f15
         /MWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jiAuuNaN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yx1-xb133.google.com (mail-yx1-xb133.google.com. [2607:f8b0:4864:20::b133])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7f4c5388052si55840b3a.7.2025.12.11.05.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Dec 2025 05:25:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b133 as permitted sender) client-ip=2607:f8b0:4864:20::b133;
Received: by mail-yx1-xb133.google.com with SMTP id 956f58d0204a3-6432842cafdso51006d50.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Dec 2025 05:25:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXyUHF5OFTQ160BiLXbahqKh6Ma+GEFsbNCabksVV9wyeravJjDejtjfHB1pafAYO8eZ8L8TrfkCII=@googlegroups.com
X-Gm-Gg: AY/fxX7/pY1dcBcQ2k6xU4GjCFt8nAFN+1qHBcxNOzF8s/dV+Q2m+OM5QM2HUebu3K+
	tB/i+TEToaozwBoonhzniFX37AOXO+RzwsLVQr6xdpg9/8v2EdNkxHVar6vp+PAAXy3qR96PTPI
	1+D+ZkEhuC1IeNWb84vdikNuENjynNhadqptl23f0s+w2ukA/H7MFy4KTBbWNtEtzVRdN0jHCHu
	JFY1AS7fbGDGr4LtdCfXz4q9D2P+Lo/RrjWjPwM+Hi08LmSwQtKryggihorWBpnIcwPhIEjJL2m
	B7l0NwKN/fFcXu6iqCNdDdQSG9NMgQ5s/8A=
X-Received: by 2002:a53:d01b:0:b0:643:1a78:4492 with SMTP id
 956f58d0204a3-6446eb6016cmr3860639d50.81.1765459536448; Thu, 11 Dec 2025
 05:25:36 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-8-elver@google.com> <20251211114302.GC3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251211114302.GC3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Dec 2025 14:24:57 +0100
X-Gm-Features: AQt7F2r5KNsATXW8d-J0gXHLFG6W_D0lOL42kIv9mnu54Km1ZPN_9U9TSDd09do
Message-ID: <CANpmjNObaGarY1_niCkgEXMNm2bLAVwKwQsLVYekE=Ce6y3ehQ@mail.gmail.com>
Subject: Re: [PATCH v4 07/35] lockdep: Annotate lockdep assertions for context analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, 
	Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jiAuuNaN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b133 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 11 Dec 2025 at 12:43, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Nov 20, 2025 at 04:09:32PM +0100, Marco Elver wrote:
>
> >  include/linux/lockdep.h | 12 ++++++------
> >  1 file changed, 6 insertions(+), 6 deletions(-)
> >
> > diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> > index 67964dc4db95..2c99a6823161 100644
> > --- a/include/linux/lockdep.h
> > +++ b/include/linux/lockdep.h
> > @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
> >       do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
>
> Since I typically read patches without first reading the Changelog --
> because when I read the code later, I also don't see changelogs.
>
> I must admit to getting most terribly confused here -- *again*, as I
> then search back to previous discussions and found I was previously also
> confused.
>
> As such, I think we want a comment here that explains that assume_ctx
> thing.
>
> It is *NOT* (as the clang naming suggests) an assertion of holding the
> lock (which is requires_ctx), but rather an annotation that forces the
> ctx to be considered held.

Noted. I'll add some appropriate wording above the
__assumes_ctx_guard() attribute, so this is not lost in the commit
logs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNObaGarY1_niCkgEXMNm2bLAVwKwQsLVYekE%3DCe6y3ehQ%40mail.gmail.com.
