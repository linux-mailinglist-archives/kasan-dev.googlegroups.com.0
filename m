Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB27D3C2QMGQE6JIV3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E2C994D303
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 17:12:44 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5a7b5bd019csf2060130a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 08:12:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723216364; cv=pass;
        d=google.com; s=arc-20160816;
        b=QlDSeFRMAxYwt92uI37xCyYgHsaHeqgzBGXg+l6gqHgMxI85j9eVj6uVkmMDGWsZ89
         kEb+8e4+yz61N0CcFeXaDsKEvqWmPSiQWQSi9YfdN653A4WBzqHeICPX18iHEvcKakIl
         VJdT4O23l8zdQL/NGyJPsFhRmfw/aivU0nEw/LGpNde+khAYxqHN8W+wF24eza5FoOj+
         eHP23xif7C4zsIiwIQKfjLbMx4/JAEbp7HFhguuyo1T7aWvmPolV8Sd0msgNGCp7jjU9
         OoskpvYIBMxJcq6Z03LUuaK2nz3n7mUR4kcFTSC1H5ClUMDqo4rngdls7PTe+fVwZwtQ
         USPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b+5ETv+ZGna9cg5dZJqxVarJUNgPEnhCLpbZ00CfT9A=;
        fh=+3kjwDH5cFQVk7d/lVUEQoV8tss9hbb9lnD1SpIZaEo=;
        b=Hn9wkHvlU7gSk4XZ+5+T2fy95s9TJ7CpsTgiA1i0lstzRyD4v/gYtkSmKdXUi22bgs
         nOvflzvHnH5M88nhzU2bmYfU1T99At9FWmjrs9bAmzbLGPrJTv3RwP4P+HER5PJ2sx5x
         JdWdoCSg7ZzIcP2ed9IcySZwSk7Z+bGHp9YMV4s1W/9/N8XadGwyNtceGYPAtSwETv12
         t+k0Vcyrr8nypc/r+umDeK+M7lYi6K5ZJfCR09Oabrqd0zas0TiLhH/skG864E+b1koN
         1w8zAPSfqIhMGpnl3s1BiPElTDqkpd6/BYdKrJNg/qIuv5oIgc8VHasHcP5v5A4vyNHE
         d2VA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RqXsYfgw;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723216364; x=1723821164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b+5ETv+ZGna9cg5dZJqxVarJUNgPEnhCLpbZ00CfT9A=;
        b=tYFoCOw99J+ZxDZ24CyrFOa+9OtZWf3uKtRLivSwFzgEqCpiU4Kyr1m3DMT3nUHYvr
         SCgYkP4gI80DIWyuHX5oc5Kpm8YFhCQgheY3/QU4Yq/GBEu/MDFVi8hORoip0yGxS2IQ
         TONDCcAQqdd+P40WDiFR+3GLjd79QyO6FwdkE63ZQyHK96vUXc9ZmMGmp78kx9nkGIuN
         ZhVCfdYLtw52kLNHF8fgJIuRT+Br8RL21BPn2LESgfGbs4fyN3uA5an7e0XRW08xSM7D
         rmEAJvo4ebApNoeMgNzW/K7752dvOBkWNM7luSfat1QS9EhCm5NZzHpblpYhfdLxU6It
         /O5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723216364; x=1723821164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b+5ETv+ZGna9cg5dZJqxVarJUNgPEnhCLpbZ00CfT9A=;
        b=FW33xgRcdFOaRULcwgcJlK91JgQb2zCMkyxt/tsf3YNW5SADm60E4E1mEAoNfobVGN
         bXImqYGBXxEsSpNqkE0/O5W8t5aLzSb5ORGvAb80TI/I/lSwvYdzEavBYmzFOkAkBbWY
         u0NddNxCXwIYGYkOJY5tD2P0tuzZSHmJ09S1aWCQXRd2OeLma7WT22YpVix74GmbYBoC
         H3i0b5WjeXckISwI0sSh7X38E6gUGXqySgTZ66cs24HJ3gB2XmB0HA8QaHk4rMO0G7d4
         vBhnofxSfkXaD2TdvUGPXH4AI7ULF1u05vALYlAARN17yR1PAI6SfWopVDR/4hHYU7nz
         V9Cw==
X-Forwarded-Encrypted: i=2; AJvYcCVlwJGTR+pwHd90usrJF7nBTrvzUiX1I+j2tRaYmT/g4T+kX/L/2o25J0ERX9cWKQvU8MYGij44UMMy9d9T1v0gmhNfNSKFbQ==
X-Gm-Message-State: AOJu0YxDS5AnIstjtkvWVUZR4CEm1tYBCG+41ydxXaIK383RXUx7Q6vC
	ToFCE563/SiPNO3NGQ3wMzueiKCPOacintA9LW4ubmE3LwvSSEoH
X-Google-Smtp-Source: AGHT+IHEeE0mNSVr17h/r84KPnDy/56Ug6YjGlg3Zw7WIJz6tER8nNW/hP8b8pgAi2QqdfHQf2mePA==
X-Received: by 2002:a05:6402:1d52:b0:5a7:464a:ac4 with SMTP id 4fb4d7f45d1cf-5bd0a659dfemr1533593a12.30.1723216363648;
        Fri, 09 Aug 2024 08:12:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34d4:b0:5b2:d0b8:74d6 with SMTP id
 4fb4d7f45d1cf-5bbaf0402a5ls987989a12.1.-pod-prod-08-eu; Fri, 09 Aug 2024
 08:12:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIlBIckIE8r6RtPHPGjRPL7c04T85W2xL4Ek/kkxxBwdhA3eCNRQVOEwWY5yfPPTt9H6ZX3Ssqm/u4e2tU9HZAbF6hVoo1b4uaqw==
X-Received: by 2002:a05:6402:2346:b0:5a1:40d9:6a46 with SMTP id 4fb4d7f45d1cf-5bd0a6b4bf9mr1352101a12.36.1723216361543;
        Fri, 09 Aug 2024 08:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723216361; cv=none;
        d=google.com; s=arc-20160816;
        b=GmdInPh8thhAUzjDQtHi3QJNr9m0E4vfwCJRMHpnAPiudNiPzaiyBzxG+9DpNyER96
         4khaFultD5sp0z9UX3GgGlngNoStSu5v94tIvQn0tqOAFmf5iD5+Ob62ZpfjeU78rboN
         inVwhkClWGJwGFHKXncZoT1De6GOk18IOB2H642UOGGj+MHQhVklEZbxsR9Vey3QhpJX
         3cDH8f/vFpeQplep4IY6/O1R6bJlGU9sjMGaTNdzSp5kRBdRlCvq6NZfiw7d7fRjI/qP
         k0VpsSHET9lgjsWUtV4ZEDtUWFFvxYoLNQI1JCNkfJs7o5TMUZhVmGV0M4VRYRMJickD
         PdoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NLUhkN4T1k329vjYkXWhULqBvElnYZGqs0JqvibKTLs=;
        fh=EHBfHtxDMpy4hqXPY+b17rdSycEdU9HKb6dSGjHYQl0=;
        b=L5XAUudZvzovOiaHpNc+Y01X72d+tzXQNwakff+R8PFr6bjSs32npYk89x/SfFCZqn
         zqZRRNksbwplWERyx0L4rLozb+pmaQQZJci6ImJ0y6DeEjjYEhNoF4bQH5zvXx4mng+k
         P/be92uFgWzNfWPKfTCo/S5mHq+4FW0LcjmRemhk63bH3wc86gm0NBFjMI3QMMjJGB8P
         /hihoc3N2BNyMyi/twqAztpodyZW6oBa9vJq6KbQ9p/JHgf5G8jzqpxCVuJ9XGFzHhfJ
         ZT6t3JbwqEJsq47Z7fkyonhRBm2bd/G+FK4lga88yHrO6N1agQgc2ICeJV/S8EzTIiDj
         lHJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RqXsYfgw;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5bbb2ea16b1si105381a12.4.2024.08.09.08.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 08:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so10907a12.1
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 08:12:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxlUMrmZtx6MXocxQEf6CGTGbe8y6ZlsTz0OJZTjcl4jYbYBh1sEUFLCx7YU6qjWSyOJO7G7czL8nfyqCj/ZrFFqodPnQxaX45Ig==
X-Received: by 2002:a05:6402:5216:b0:5b8:ccae:a8b8 with SMTP id
 4fb4d7f45d1cf-5bc4b3fd7b2mr149224a12.3.1723216360417; Fri, 09 Aug 2024
 08:12:40 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
In-Reply-To: <54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Aug 2024 17:12:02 +0200
Message-ID: <CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
Subject: Re: [-next conflict imminent] Re: [PATCH v2 0/7] mm, slub: handle
 pending kfree_rcu() in kmem_cache_destroy()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RqXsYfgw;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Fri, Aug 9, 2024 at 5:02=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wro=
te:
> On 8/7/24 12:31, Vlastimil Babka wrote:
> > Also in git:
> > https://git.kernel.org/vbabka/l/slab-kfree_rcu-destroy-v2r2
>
> I've added this to slab/for-next, there will be some conflicts and here's=
 my
> resulting git show or the merge commit I tried over today's next.
>
> It might look a bit different with tomorrow's next as mm will have v7 of =
the
> conflicting series from Jann:
>
> https://lore.kernel.org/all/1ca6275f-a2fc-4bad-81dc-6257d4f8d750@suse.cz/
>
> (also I did resolve it in the way I suggested to move Jann's block before
> taking slab_mutex() but unless that happens in mm-unstable it would proba=
bly be more
> correct to keep where he did)

Regarding my conflicting patch: Do you want me to send a v8 of that
one now to move things around in my patch as you suggested? Or should
we do that in the slab tree after the conflict has been resolved in
Linus' tree, or something like that?
I'm not sure which way of doing this would minimize work for maintainers...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g%40mail.gmail.=
com.
