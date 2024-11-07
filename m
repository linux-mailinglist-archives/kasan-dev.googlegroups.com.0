Return-Path: <kasan-dev+bncBCS4VDMYRUNBBOVLWO4QMGQEBIGB7XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 558DA9C0979
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 15:59:08 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5eb8b4b3eeasf748922eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 06:59:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730991547; cv=pass;
        d=google.com; s=arc-20240605;
        b=IuzWx2lvnor/YV+OlUmrxGcFnmKn+exeOr3bKw2WjIvAj3cMB08WGp5UK/Axoe8x1E
         pFuJKoEqz4h9ITHpj4U/L/xVqBiw/oWneL/5Q2UpbV9lxyeajSXerM3EvxYnRtJb9i4z
         3OcAmA7FoYAhCp9cRWvjbeHBz3IyAaBy6/vcL3WG5gy15u9RiGzDm9CE289UEOgFh55C
         EmvB7JD8tKZncN0WBJkEzW07L/k3JnXG1EN4mC4uX3N6/HiPpYhlt3h5fJQZYupnl6Es
         pR6o49F912KariuLW5ZdHF1eg1C++427z96k6+lje49GZxqhxoMkQRAraYgCz8lDlqmO
         rYTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Sntp49g1UakBOUrb0GXKYNAFkG7X9Tbx4yfOr2ZUzMM=;
        fh=trSHjkq8Zq7gSK8qJx0TaXBHo/0CBzcnCM0jEE98JXY=;
        b=LsMSx3kUBF3KolQXw2jsajFou2Ve5S1ZcyrCTHozdiyrWb6tZRSc0KYxKniPIANgfv
         fH5R7X1EkZvMet3POKirTxvXOw+QFRz8Itx1TuKPGmwGQ3QFH17jA932kVU7quHEHr3V
         gfOjmr20aKo68y6rTr/XoFjC8BRyOMgAm6YbbynvWpWRTz+FxLxQ3ucXmy3YrP7/Jtuo
         vvim0WmGW4iQdB4cwbcpD8FwZrO5T3uthA4A/bZbFvxeiEaDlc5B92onrj4SILDPrc6y
         3zZaoUIp3eoOIzwVqE7Stbm1gvFzM4dSdr8DlphNUFdjYCPkljBFXl8oQq4vF8yLSOlX
         Bc1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qyA2iR39;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730991547; x=1731596347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Sntp49g1UakBOUrb0GXKYNAFkG7X9Tbx4yfOr2ZUzMM=;
        b=pipEW5c6tpOks0HDfkx5IbPRomxZ9dTmJYqmKZdfe3iVpEI+IWAYuRBPatq2cOfKhk
         dbd+6bm0flxOrFLBHQ9JN5Yr0cYTPDhOBAFEC3rBPu0UgTCx9VwVGb9M+geNGhQWsgK+
         FEW6BSb9NgyX2ZeUeY5ndNJwHElQiWe214BC1svLFDn5xNlrFwzF4udQW/ZYtz5G34NV
         LVACPGCsqwfNp2TWMBwH1Lxemt1emUnSQvxSpsBtw4wMdJZgyBy7FDGSY2ojIzkXJwwl
         bSm6bOb93fqz9+gIUtraw2sNtRVPzH2Y5O9yzEHEoHhi38pnxL9iAgICBsEzt50UfFUB
         xvbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730991547; x=1731596347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Sntp49g1UakBOUrb0GXKYNAFkG7X9Tbx4yfOr2ZUzMM=;
        b=F1zYHbAHSZMEuW8xaJ9Un3gOB26HnEyLbZxvIJLEwsOnrdirdjzWdGkRB4tYEu6DkQ
         SjuhghLt8uH8P3sQ/yDCCGtPPdfWhE0OcK9bk5MUlPWnH2K1Phq+L+i8IpXi8k768vW+
         KuShvJdqG8ewomR/4sXZRtMz/d0KNDmYJfZrwbGwqdK0whpQaaAIFIiHXar9lS4dyCkq
         qbVOpKQ8vW/tU7vrBbB2qp0bV5mX7PUKLcQTDD1A/EX7Xxp+l+5Hae0ffQqFetc+FD8h
         9uHWbESKCjS0Pxe3UO/atbgFZhJamJacP3IXBFDLfA0cx4pKfaSeOGKj5R87MNrn66NT
         vRTA==
X-Forwarded-Encrypted: i=2; AJvYcCXEVaCVj92CErOlGnxlTp3XF11FSoTuiwiSYpD46nJGl+ZJ2f9IS8yQ08AcNAXPxM8VP1vJRg==@lfdr.de
X-Gm-Message-State: AOJu0YzZApYLYEVsmIIKal6y3lTjOC+61AFUkNFiSDj4JhjoNVKGUqdz
	h9oe6A4oyrZvoBQ3fX9vwrepTQ7ZPvn4uJVMm/MsD5P5efG1mZoV
X-Google-Smtp-Source: AGHT+IH+S1ZZ5aTye2Y1tf7xHqYaVLDodhJVl5JQHxuVaG1Sojt6vxg0eC9JqbyIjlU+R2oLIv6PYg==
X-Received: by 2002:a05:6358:5d81:b0:1c3:94:8fe3 with SMTP id e5c5f4694b2df-1c5f98c4b7cmr1154745155d.4.1730991546637;
        Thu, 07 Nov 2024 06:59:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:d02:b0:6b7:8ba3:a39a with SMTP id
 6a1803df08f44-6d39353fdecls11263546d6.1.-pod-prod-04-us; Thu, 07 Nov 2024
 06:59:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVptWeGzTvBSxnnYDzX8dgtbVvHd0vTF9u5dTKtiICGODcTzpKS/EnLCEz1XfX1YTxMb9VUH6Wm1oI=@googlegroups.com
X-Received: by 2002:a05:620a:2405:b0:7b1:4536:8dc7 with SMTP id af79cd13be357-7b2fb9cc0e1mr3344842885a.41.1730991543244;
        Thu, 07 Nov 2024 06:59:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730991543; cv=none;
        d=google.com; s=arc-20240605;
        b=bjvNSPuzwERJIha2ru2grjAbkVJ6BFvghYV/HRl0EVLMBwGRrZTmAguz6zy+wR5AXc
         PW6VqdDB6pV4ZSu3hGPPvbrZ9u7qDaCSDMVFqhWZZPavm5N4GJsUQQWX7RDwe9ru3AJP
         5mLtsM6ir8UgyIeA0fLua9C+hjLmPxvd8xJwJAtyUKoARF04G/i+sTZX85zgc2f4kwzC
         I9ZosLNTqcEyA4FLYEeZGgPEKegmZCSKW1EHhkAdTNiWfOz2LfnKysGu/PvEHvBrasgq
         AwLvopzk7/KT+UHExuKT3MRLw1u9/5JknDR+4ZG9idMfKn+sKfTpOjNuxIS1eNrhiahj
         OwWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Y79JTinDelt2DsWBTvIqrPcUjnrByhcBCVsYq9ZhUkI=;
        fh=gOeqIDRGq3LmMrDEvoXOvAyaoj8gr6AJrF8eTSaK0ck=;
        b=NBr0AhOb9TKu3YpmJuJe1M5sq3ssh2dvYwSxOaH6bdqFNk4RSKpj/gvYDweVlh41yD
         OK3u8WodqPmiKpwL64UAENEydGaPVmXZ57DuUqBTY9C6wTLQR1mogZOj6QSgDORD1WPC
         2w/vZDZDNBSYDdRZQ7tSFeAwa672LIbxCwykON5DvRhCpxXAM9ujmYHNHr2+HRP6ZoTb
         hhvBwGtuGPOO9ps4y6gw80AUaC66rhJbxL83XsJa8oVKdW6EebOuEUAcZuSP6rHDwFL9
         uJqPg3QjgHqEJP4LEl+OPH/bErHKXJ3yOVsjNAITG1dJd/z+L9YOhRcT8gH9p7NAvFAR
         2Czw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qyA2iR39;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b32ac39e70si5550285a.1.2024.11.07.06.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 06:59:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 15BA55C57A4;
	Thu,  7 Nov 2024 14:58:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6505AC4CECC;
	Thu,  7 Nov 2024 14:59:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0EDB0CE04CE; Thu,  7 Nov 2024 06:59:02 -0800 (PST)
Date: Thu, 7 Nov 2024 06:59:02 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Boqun Feng <boqun.feng@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Message-ID: <9cb78f76-7ab9-4b60-974e-8620bac69424@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
 <20241104105053.2182833-2-bigeasy@linutronix.de>
 <ZyluI0A-LSvvbBb9@boqun-archlinux>
 <20241107112107.3rO2RTzX@linutronix.de>
 <45725c86-d07f-4422-a6fd-c9f02744ac75@paulmck-laptop>
 <20241107144300.gbzCzBRf@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20241107144300.gbzCzBRf@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qyA2iR39;       spf=pass
 (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Thu, Nov 07, 2024 at 03:43:00PM +0100, Sebastian Andrzej Siewior wrote:
> On 2024-11-07 06:08:35 [-0800], Paul E. McKenney wrote:
> =E2=80=A6
> > This statement in scf_torture_cleanup() is supposed to wait for all
> > outstanding IPIs:
> >=20
> > 	smp_call_function(scf_cleanup_handler, NULL, 0);
>=20
> This should be
> 	smp_call_function(scf_cleanup_handler, NULL, 1);
>=20
> so it queues the function call and waits for its completion. Otherwise
> it is queued and might be invoked _later_.
>=20
> > And the scf_cleanup_handler() function is as follows:
> >=20
> > 	static void scf_cleanup_handler(void *unused)
> > 	{
> > 	}
> >=20
> > Does that work, or am I yet again being overly naive?
>=20
> See above. I can send a patch later on if you have no other complains ;)

You got me on that one!  Thank you, and please do feel free to send
a patch.

Interestingly enough, this has never failed.  Perhaps because the usual
scftorture run injects enough idle time that all the IPIs have time
to finish.  ;-)

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
cb78f76-7ab9-4b60-974e-8620bac69424%40paulmck-laptop.
