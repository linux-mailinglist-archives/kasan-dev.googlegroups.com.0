Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBYPMX23QMGQERSYJVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EE7097E046
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 08:17:07 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5c2504ab265sf1430929a12.3
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 23:17:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726985827; cv=pass;
        d=google.com; s=arc-20240605;
        b=I694fBJOwjSN4qMLNHJGCc58fi9C6HaKxgnvpn/kE5raTZbRNqbKg7LuND5aXdgIdK
         fbo0ic9/kFI5NGddTKulbljkO/7WXhbS3wUBgq/to42AoICsKqJfKry8N2yAwW7cLZsu
         Fg9UbuDSGSexE+ScBOYNV9wspFrE/keWkkL03ec6aFbWI+NSeswvekDRpmwpq8G3KQLq
         d1CLRc0wPL5WzQHU/XgUbmf19ZbR02/277+3KnqhUcXycEQwqomWN4aQC78aKC9zccAc
         31fEBoSgTjGz74zrAW3fHhUPXVYElP2197TjntwCpQKRXyV54HTNkTOEdEkQ8mvW9U/z
         6dkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Ffb0TKX3qOIH55Cgnlw/awDr5XKZRd6EBcnOT339jr8=;
        fh=kXSqldNz5PIXBmPuMRBVjhpU5VrRmzVagbBRfXW26oo=;
        b=W4Y0km/v0Gk/5qWh/16YpqNRif5q4P2CWy2EwkKJaj8eY3D3iiZ1aW6oK6UHNGqIF8
         nwlMqUOGAHJZ44+3z3FAGCpU4OR1/5LOOfH9zK5E5i5VHJpz9OZFCUuosf67brc2nMS4
         /7LAbKT3Hdk5ngy8EpENjNjO+E2t1QS3e+4F0wOAtCsAMqyR0Sb9MmOs1xCwas9Ho33W
         hfjVQ6Mm2lgsmdPhhCgM0aUEMgsi86px6zPSK4rGJYGQ8tCVu+Tq5MLC9P1LF+eBuvU4
         kkf3iSBC3DLuw1Ke/0pVPYa1fT62YKqE1MNw3tQ3asQudxSybcLv++mHIJE+ZC2A1l8v
         Zzfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LtFbZ3bE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726985827; x=1727590627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ffb0TKX3qOIH55Cgnlw/awDr5XKZRd6EBcnOT339jr8=;
        b=xnRTNYmiKig9OOejroi3BPHgQK4PJ0JEfdJcvXlPyOjHEP5L5TN7+rEnJ2TAGTKwwD
         f+X3X2f/S6kbK4GmrM6DII7kYUuPXG/XpOYnu9gRf5GsMbTXU16iEgng6GSinfDpkS9D
         e9m9KLe3ob7VefNE0dLQAq0UVLRP3DWRK6P5HBUSVXlEJqikTt1kNdNC54K3hGez6Fnc
         AqqFwsjETEvxZhVry2yWYP9eTtWuCcWq5dAHUvVfwD1bDgeXy2TPEVrOD0ylFXhWV0YH
         F/N3/JXtmOg612k2TgkJVzp1Mc4VT8Rw+zmXSlKrgz/hWNLvg4bCnrPqfp9qhMyKVeBw
         nomA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726985827; x=1727590627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ffb0TKX3qOIH55Cgnlw/awDr5XKZRd6EBcnOT339jr8=;
        b=LjiCl9/7R2jmlTmp2yctAm7xhPCCqlG5IMRYgEbTs1CkL3EhyztnIzXBl3re0Qq4gC
         vMM4uh5kZtZMQUcvqwCJ1fNKA6CiPus6TG1JAOgRSqGWCkliRoktNuxMQ3XYCTgUzUvr
         eBwSWx0ewb3R2ceEbD1PM+1i63CXQhfz4BmzB035U8p2GXeO6tUjXjSJikl+fqkwtm4i
         40/jCI1AQhVq87rd41ndae/KgUO/lzI/8pMLS6G8m/xW8eRwoTbzmOObWBNycUybirAg
         gVpkM6KYzb1EoTVQwsKRRPDQNZiCOTZA43ELIX6YfzSbt5H0JBe2MHBAba3EJOqmZpRS
         G82A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726985827; x=1727590627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ffb0TKX3qOIH55Cgnlw/awDr5XKZRd6EBcnOT339jr8=;
        b=jlbYbNwrpyp6zu12ph1Lk3dd8vxV9xLQ0LgrVv3J+rxl5Ugwzfbz4/RqrXq87ZtItj
         WQdIUPno9gcUbslDuT7ct415qI4RpmHh1jdBjH7yhTLvm0j4QTKUmbTcAzhKACjKztaQ
         CJQWUk8eGYa8Slu6EH8n+60C0QxGyFY9Fto7pkvNxyIRIpze/CgODyPe4HHGbjJhoBxI
         +c1/PnG23sI92Ezazo/xRGlVZ7Gg1HhRyLd+jSXMEhpy1nzTa1MuWt9gorBx9SMRe3G8
         wUfHxebFTlCWMYvX6KnsbqvP5tri6l6qJdT7ZuxCfS90qqyX8vvXLgHBkXQEEA6Ku6z3
         zE8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNzQ3eQRlyMKbvEU7BN4BSEct+i/cK8VNQ12KHNB5rIi47NezpS8FAf06FmoW2zZYUpPViYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+Hgm4hcm7bRIG9k1l11YM7F/HJCwx2+A8oZIsubFgbC4tj3Xw
	yvx6OISfDmtnD35sBCXOS3Dyf//wkhCz8S4bOjCcSPmMikJ984sF
X-Google-Smtp-Source: AGHT+IF0OkGPgQhTxsQDRsAxuFlonNhNyI+OPwFKsZlQQuiN7ekpSiM08fOyNiZLJ9Wnkd3j7JVZtA==
X-Received: by 2002:a05:6402:42cb:b0:5c3:d0e1:9f81 with SMTP id 4fb4d7f45d1cf-5c46484f429mr11710581a12.7.1726985826111;
        Sat, 21 Sep 2024 23:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:27d4:b0:5c5:bb82:81ba with SMTP id
 4fb4d7f45d1cf-5c5bb828454ls214541a12.0.-pod-prod-05-eu; Sat, 21 Sep 2024
 23:17:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX58xkJBaLqbu+h3eevs+DA099A9bWBr8nmIBh4dz4eVZVlB2Rylmx1CJCe+TA0EBDT2Px+T883jIs=@googlegroups.com
X-Received: by 2002:a05:6402:354c:b0:5c3:d0f5:86f3 with SMTP id 4fb4d7f45d1cf-5c46494379bmr9708394a12.3.1726985823906;
        Sat, 21 Sep 2024 23:17:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726985823; cv=none;
        d=google.com; s=arc-20240605;
        b=V0K2I2/UZ78rdZqvrZBWOvg6Zmj2LtsUe7uXQX7sPk41fIpG4sGNs9zzeZ9xkEyRNo
         z4pXKTYLNNcHdI7i9HIkFrG/usCRbyyYCGvxmteN3TxOaqU3a/ttqU4HpBUopGNsGcg3
         SizFHyLAgDrp6Ynlxrg+BLgdJs+8q5LaFxqboQUDc8HQr6w0u/zIySUrVUPO3v/jMcnl
         umvdq0wkeiYuNZmtI2DbluhyE2oqeKh9WaD5n4sB9LVkqZ0cTKudDQ5lHcJAeoFVE+gj
         ZmMGDaxmv4Xr9sHEK41a8AInmbyw3OVTm1QsrHRhFHTjAvrfVFm7M8xaKYYpbS8I6u5l
         q7qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Dn2ictoSHLp+l35mgClPZL8BskA+nsyYSb4MVFpd50Y=;
        fh=+IRvOBVYz25p5+GwtUUQnk1P0RPvMj3dOPXOg09JOO4=;
        b=Toun9od9XSnoDRRAu6JVIg9w0Mr4LNe/oewta6QXRBjqYtM/+WBot2B2MN95GDHNev
         izfisTUhE+A3RLF/w262ykFCVfBH0B9DIqUtV1dQLrKqB0hAHv3LKPiigwD6q0sC39Vd
         UC0Jj+29CSDJQ61h0qtUamF/wgceCRVFyBzeFblxeiV/9GDOZkSejO04lk6ygE3P+FOM
         Su91I7TI/BBZ0nUDHZmWwJq7MWNla4tB5e+jcBO3ohzsx4qydF287XvHPgI9MTMA5NxV
         +jbtO5cLVORE6WjXO8qP/3mA710YId84yYyR8kkMXBeOvVOybn/br/BwTf9ilTtaKl5O
         lpuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LtFbZ3bE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9060f4fea9si41397966b.0.2024.09.21.23.17.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Sep 2024 23:17:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-5356aa9a0afso5270471e87.2;
        Sat, 21 Sep 2024 23:17:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFSfWXxS170TM/U+wFDhuZGK8JAexUpfkO0QZbileU4QxhKEQQ+o2PAhV7DRRqoGu35Uh4KLLINlep@googlegroups.com, AJvYcCW6/nj+Pej8BCkz08oTRp+9uU9Sg6X9tdwVN6l5SVzewppzfcdvWq0El8oPnRziykICCTY4a+bUwm0=@googlegroups.com
X-Received: by 2002:a05:6512:6d1:b0:52c:d628:c77c with SMTP id
 2adb3069b0e04-536ac32f044mr5163363e87.43.1726985822724; Sat, 21 Sep 2024
 23:17:02 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
 <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net> <07d5a214-a6c2-4444-8122-0a7b1cdd711f@suse.cz>
 <73f9e6d7-f5c0-4cdc-a9c4-dde3e2fb057c@roeck-us.net> <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
In-Reply-To: <474b0519-b354-4370-84ac-411fd3d6d14b@suse.cz>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Sun, 22 Sep 2024 15:16:50 +0900
Message-ID: <CAB=+i9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL+UhF2w@mail.gmail.com>
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and test_leak_destroy()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Guenter Roeck <linux@roeck-us.net>, KUnit Development <kunit-dev@googlegroups.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	rcu@vger.kernel.org, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LtFbZ3bE;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Sep 22, 2024 at 6:25=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 9/21/24 23:08, Guenter Roeck wrote:
> > On 9/21/24 13:40, Vlastimil Babka wrote:
> >> +CC kunit folks
> >>
> >> On 9/20/24 15:35, Guenter Roeck wrote:
> >>> Hi,
> >>
> >> Hi,
> >>
> >>> On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
> >>>> Add a test that will create cache, allocate one object, kfree_rcu() =
it
> >>>> and attempt to destroy it. As long as the usage of kvfree_rcu_barrie=
r()
> >>>> in kmem_cache_destroy() works correctly, there should be no warnings=
 in
> >>>> dmesg and the test should pass.
> >>>>
> >>>> Additionally add a test_leak_destroy() test that leaks an object on
> >>>> purpose and verifies that kmem_cache_destroy() catches it.
> >>>>
> >>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>>
> >>> This test case, when run, triggers a warning traceback.
> >>>
> >>> kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects w=
hen called from test_leak_destroy+0x70/0x11c
> >>> WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0=
x1dc/0x1e4
> >>
> >> Yes that should be suppressed like the other slub_kunit tests do. I ha=
ve
> >> assumed it's not that urgent because for example the KASAN kunit tests=
 all
> >> produce tons of warnings and thus assumed it's in some way acceptable =
for
> >> kunit tests to do.
> >>
> >
> > I have all tests which generate warning backtraces disabled. Trying to =
identify
> > which warnings are noise and which warnings are on purpose doesn't scal=
e,
> > so it is all or nothing for me. I tried earlier to introduce a patch se=
ries
> > which would enable selective backtrace suppression, but that died the d=
eath
> > of architecture maintainers not caring and people demanding it to be pe=
rfect
> > (meaning it only addressed WARNING: backtraces and not BUG: backtraces,
> > and apparently that wasn't good enough).
>
> Ah, didn't know, too bad.
>
> > If the backtrace is intentional (and I think you are saying that it is)=
,
> > I'll simply disable the test. That may be a bit counter-productive, but
> > there is really no alternative for me.
>
> It's intentional in the sense that the test intentionally triggers a
> condition that normally produces a warning. Many if the slub kunit test d=
o
> that, but are able to suppress printing the warning when it happens in th=
e
> kunit context. I forgot to do that for the new test initially as the warn=
ing
> there happens from a different path that those that already have the kuni=
t
> suppression, but we'll implement that suppression there too ASAP.

We might also need to address the concern of the commit
7302e91f39a ("mm/slab_common: use WARN() if cache still has objects on
destroy"),
the concern that some users prefer WARN() over pr_err() to catch
errors on testing systems
which relies on WARN() format, and to respect panic_on_warn.

So we might need to call WARN() instead of pr_err() if there are errors in
slub error handling code in general, except when running kunit tests?

Thanks,
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9SQHqVrfUbuSgsKbD07k37MUsPcU7NMSYgwXhLL%2BUhF2w%40mail.=
gmail.com.
