Return-Path: <kasan-dev+bncBCU73AEHRQBBB6H2QPFQMGQEQNUDMGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D41ED0A343
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 14:07:07 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-8b6a9c80038sf458220485a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 05:07:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767964024; cv=pass;
        d=google.com; s=arc-20240605;
        b=T73jgNJZcwWc8VwEuzRoKfXm1BGAMLTIrcu/Mfn6/MouyLJHKLjVOkk+JG+tRWJmbn
         C/ygOiKe/zKoEffYQX9RgUSkmICC7aDlgIbgxq61V/WgRUYAG78TKkej1JB6tzziFCbx
         iYD7LqcKMWMbc6OXNPe/aHiqOvGsfW734rlMqVrsfWhFlbi2HdL6Kbvc6f74ufaOepGZ
         kNUQbA09yv5htLB+z16X6BWJVIi8iQfnCas24Of/yn8jA78sgSDeKPp9TeDuDwlz87Vv
         AdRJWJa+qkCykmDFLpxiHOgvLqak8KqMljxXhzG+hdkX6rjsM5NghjD3p5EORJRqpxyT
         7k7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kFaq1qw03CaXPSccdb7x5BAT7s1svZvYpVesB8jc17A=;
        fh=YExPsKZcSLKrZ3qlExZbIUpZeIWF4mbmLv5ugkiteOI=;
        b=BeE7tY2lFkroyC8gtjpSTN/fqbNH/j9HA0pOSzHIibEOHoVpDZM9bLIPk57KqAxhVu
         NHWrYcnpgBYUgzdsX2xKJJsqUfG2oU3MG48cIKIDEXcCb4A8maRjuuICKm0EHwA6xzBi
         VoAnOIxuy0ICKh+zqeJmlsCZKOBQW3GSu/hv9Aco6ijrTMrHCqp3J66o4VIR4y5jzp/+
         O7OUjXkZmm+txgvfexQ9fIlZzTl40vLaXwiNR16h/TkEMBgcnr4pyEehwmBZX2BWC0Vr
         +ikytXw4r0QpqgSv0HRZc9OygVzE0T5S/ML+ISy3Aex9ZXWElV+06aXqdkl3llADZ9uX
         XqTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rostedt@goodmis.org designates 216.40.44.15 as permitted sender) smtp.mailfrom=rostedt@goodmis.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=goodmis.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767964024; x=1768568824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kFaq1qw03CaXPSccdb7x5BAT7s1svZvYpVesB8jc17A=;
        b=cjc0QAPtNsnQPdURBu/9cWY4YWs8LCXRp4OoJhvQLqqpT2HZ9fcZZH4Q4lRuf0tKPL
         mZFTXuKe569k23H00dItUSzio6n020hc3eUPH1T0FKxg14f+QXq+jbA9/nV1MySHf1H0
         zfTgoWRv9cJLhuqnOwJWqpZnl4/lqeGzbM9t/Gly5DDsepnaac0ro9wdj0C/0PF6paWU
         NOJEnmDoRefxEi/EYh3CCeQiW2mksOHDVtPy9IRceTH9fq2F2FVhivRBcM+vZ2kuUs/S
         57EWI5aq6I3+UZ/mX+uNwCs8BsyDMq88cJ+IUkTfHirvm/IaQKaM7vkTzdEiEO0BEqnJ
         wukg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767964024; x=1768568824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kFaq1qw03CaXPSccdb7x5BAT7s1svZvYpVesB8jc17A=;
        b=jgjgzAsyjlPPs6svF1L76DsAtUr0BGbDh49hM45axo2OroJ1Ar+ZBB8Z4RpdcGXPZs
         OsGDzgBPr7gP0UoypWkLW3iXPhk0lBzFTrtrl5tRW1Gym/eloJi3lFZI/OJ6J3bjqoZK
         /206lA7BcYs1DV1qyrAJHcMmiEJy//obrWtmuVPrJLEc2kJQcGjItWPF0ir0fOWmXoR6
         3JLmexazIHo7ENt+Y/ZbuKJ67A3SPA69MbvTHjCKS9EOf6kjju24nyJk/KwbcsOjz6kJ
         rdP16o5srIu1ANLcPj5gib7I6E1W+a2d+JMX2LrhabbQQmAeK7N1vUNFkoRI9mj++2IM
         1XJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOAKRVboBG897sIS7aJDR1NuAiDcos1+xBQmGlkjP4apt/Ef9bbcEl8FXnowr6sADgtbXv+A==@lfdr.de
X-Gm-Message-State: AOJu0YwNG46nowRW6jNbTZrROkPqsErTwVPpcERe3fXYlMA963/S1jgr
	eQTg7n3oKcrrBQph2q4ga4B1Csaqeyt6GrvoIn0kevm33wmtbae0DMbB
X-Google-Smtp-Source: AGHT+IG2EiUvOPegR6Zv10BLODqoFAkCFnfn0uYH8Kq2YaUYrErmO1S18fKz8UXEdg+3/B5PnhaCMw==
X-Received: by 2002:ad4:5ccf:0:b0:88e:c723:6f7d with SMTP id 6a1803df08f44-8908426979amr142379176d6.34.1767964024288;
        Fri, 09 Jan 2026 05:07:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HPV73BEonCW5nPifX2qEroS7enSHNsg6JSp9gZpiwJZw=="
Received: by 2002:a05:6214:212e:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-89075557aebls71720206d6.0.-pod-prod-08-us; Fri, 09 Jan 2026
 05:07:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzcbto4K1L5rNmFGn8KG/exZ9FGJXEdswmJwygNWoI/eWa8zi/mgxltTNjhdgsrMU/oS5fxtwge2s=@googlegroups.com
X-Received: by 2002:a05:6122:32d1:b0:54b:d7b6:2eee with SMTP id 71dfb90a1353d-56347fb4942mr3229468e0c.11.1767964023121;
        Fri, 09 Jan 2026 05:07:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767964023; cv=none;
        d=google.com; s=arc-20240605;
        b=gZjFJHHXwCAP+Ken29H0fEqtPA5erLJR/9VasH9nFW04dI28SKlVEkySqdxTAldfAn
         9YZRON+woGkJzqFK6mkHjNEx8wXxDPB9c88Rv541H5sU2Un2TOx9sjPnQRNIOkbBA+xe
         sxH04DNtB/HSNC4OYfDvd3J6VE0+WrhNRhdmxS4JKSVvvTLEO8QsjK8KdvgdKl+dEEjx
         ryB69Avi1rUZHMd0dcD0V66Z8oCdGSZFfKtAJQPRlYZtx4uWVfRS0Pjtv/JodPb8/7Tz
         IWW5Lr/3yoHAdZ7XWQBL9MYoDx8O1UdyORpAuEdeuPztuA4EHkhhpNzrzYgkhlnVFqNx
         cQxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=6M6S2V9hKywkfT+wbmVWWko9S8WTPsC+i25HW/je+LE=;
        fh=dJFApguhC8+rse3x9uzlCgRbMEmwcFGxcdSfAd8+/GA=;
        b=UoB0r+PvjnR9Qk5Lem2gJC1kYwQTolEloiQ79mur8ZY+BQH5BSScpdkVNAaYItezPi
         EV4gGwRNMWOKp+y2ANspS4zfGN/dai6aLcHR/SJJPzhrNONLKr13XHjIKb4qBDSy2Grg
         MIO3YlQdWfxmFWJDtaFB2gf7sTmTW9739ipaPbFzoe4pDZx5t/EDfWIIcembgMNLfYV5
         Wyikb83s4s/4eu8dgRWcBgKTe5mXdMu2asQRiedH+QjVHX84qIHvAhi0b5ApxEp8uenH
         Svzahiwer+XhPtbge5Cf4A7MXS4QWIiCvnk2cpqde5G2XSF0KQo9xVHjn9+hvvDvTskR
         sczQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rostedt@goodmis.org designates 216.40.44.15 as permitted sender) smtp.mailfrom=rostedt@goodmis.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=goodmis.org
Received: from relay.hostedemail.com (smtprelay0015.hostedemail.com. [216.40.44.15])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5635f1e45fdsi113681e0c.7.2026.01.09.05.07.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 05:07:03 -0800 (PST)
Received-SPF: pass (google.com: domain of rostedt@goodmis.org designates 216.40.44.15 as permitted sender) client-ip=216.40.44.15;
Received: from omf13.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay05.hostedemail.com (Postfix) with ESMTP id 32BC75ACA9;
	Fri,  9 Jan 2026 13:06:58 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: rostedt@goodmis.org) by omf13.hostedemail.com (Postfix) with ESMTPA id A03A520010;
	Fri,  9 Jan 2026 13:06:44 +0000 (UTC)
Date: Fri, 9 Jan 2026 08:07:15 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Christoph Hellwig <hch@lst.de>
Cc: Marco Elver <elver@google.com>, Bart Van Assche <bvanassche@acm.org>,
 Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>,
 Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, "David S.
 Miller" <davem@davemloft.net>, Luc Van Oostenryck
 <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, "Paul E.
 McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>,
 Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, Eric
 Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, Jann Horn
 <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg
 <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, Josh Triplett
 <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, Kees Cook
 <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn
 <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, Mathieu
 Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda
 <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay
 <neeraj.upadhyay@kernel.org>, Nick Desaulniers
 <nick.desaulniers+lkml@gmail.com>, Tetsuo Handa
 <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>,
 Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman
 Long <longman@redhat.com>, kasan-dev@googlegroups.com,
 linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-security-module@vger.kernel.org,
 linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v5 10/36] locking/mutex: Support Clang's context
 analysis
Message-ID: <20260109080715.0a390f6b@gandalf.local.home>
In-Reply-To: <20260109060249.GA5259@lst.de>
References: <20251219154418.3592607-1-elver@google.com>
	<20251219154418.3592607-11-elver@google.com>
	<57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org>
	<aWA9P3_oI7JFTdkC@elver.google.com>
	<20260109060249.GA5259@lst.de>
X-Mailer: Claws Mail 3.20.0git84 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Stat-Signature: xo5wgurkrpym6obtb6d77z4eqezppqwq
X-Rspamd-Server: rspamout02
X-Rspamd-Queue-Id: A03A520010
X-Spam-Status: No, score=1.40
X-Session-Marker: 726F737465647440676F6F646D69732E6F7267
X-Session-ID: U2FsdGVkX1/Yuy/xlEJ4FchBK8FGPRyEzpxFlfJw7cM=
X-HE-Tag: 1767964004-230449
X-HE-Meta: U2FsdGVkX1/mK5KxM694kU63Rdn/iZMuRkOJbrkqpBY9gVZfABZTPJnGV+GXEC41f1CraOV8yVb8JwE6ex2vbV4aoxOT3VLKLF5Thmk+n9vBrpyyHnFtGdrkM3exSJJfO3l1oVR97XyrKK8Hkfj/5sdmmAH04zSgJDoYobVhPLcJaqT68Q0XdWN9PbI1sOsFrspcL2fHNGmrmo/p6rwpjlSypMilSM5I5ewwgNFo1hyODxJhs+YqTtFErumcaYRIY1tmmRLhIj0JwjIBTskcyNNIQY/Qv4I7CCtQ3inbL2pdKc5Mrj40SiW4O33CrPwJHtQvEPJd1GEXqrywF3gfPLCE0T+XQaZa
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rostedt@goodmis.org designates 216.40.44.15 as
 permitted sender) smtp.mailfrom=rostedt@goodmis.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=goodmis.org
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

On Fri, 9 Jan 2026 07:02:49 +0100
Christoph Hellwig <hch@lst.de> wrote:

> On Fri, Jan 09, 2026 at 12:26:55AM +0100, Marco Elver wrote:
> > Probably the most idiomatic option is to just factor out construction.
> > Clearly separating complex object construction from use also helps
> > readability regardless, esp. where concurrency is involved. We could
> > document such advice somewhere.  
> 
> Initializing and locking a mutex (or spinlock, or other primitive) is a
> not too unusual pattern, often used when inserting an object into a
> hash table or other lookup data structure.  So supporting it without
> creating pointless wrapper functions would be really useful.  One thing
> that would be nice to have and probably help here is to have lock
> initializers that create the lock in a held state.

Right. If tooling can't handle a simple pattern of initializing a lock than
taking it, that's a hard show stopper of adding that tooling.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260109080715.0a390f6b%40gandalf.local.home.
