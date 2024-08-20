Return-Path: <kasan-dev+bncBDK7LR5URMGRBI74SK3AMGQEW3O2KIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ABA5958BD7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 18:02:45 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-52efdae5be6sf6109242e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 09:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724169764; cv=pass;
        d=google.com; s=arc-20160816;
        b=yqPvqjkgg6Ax/smNU76XHE5TxM0W2+CN0O4lUelBxmhwweq1dPHvVuuc3969cZtNvZ
         4qnoT2TQyC9yghTFwqXhD7zeRlFM6kzcNKL8S4+XbLteV2FMUNCcsTYlABrTJOJl6eIa
         Esq5yJ5k7BGaU/BziwgOJw9N1UFEamzWJ8ofYJj0sXB+0cmS53HBOtIzHWGow3jJtDPk
         2FFXVvChex/ZmNnJhew1u4c9iHm5JijxTOcrzlMvOBejTxpjqwpLM5Dqk7oiyvRxYBge
         TtIGvjHuDqUg5EtwolJomegZKdThZs9wATqtSUbwO27ICCo+fWDszZ52jJnDLOcIqjZK
         VhmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=sy5YCduC3Zm5zgSYXYt1SmLRrlSVWk08UkmeBPH8HG4=;
        fh=B+JTW4p0K2iFz2wC9nwjseAnoh4h50h27f+JSjPrhnY=;
        b=oXaK7ttN4eaCBdmhiCmMSHS/JzCddHbN0StNJUATR/hTfB95KvxhlDRmCybI6/Mh3E
         DPUP7bodzvdz53QZ165odKWJi5CHPh1YYHVHBrsvslOOn3ozx3gWVqZ6BGdC8VOJo7lm
         +xRy+bTQfGBYTvDLptowYvXKLZpGA9IAzpa7Hb/syfIFPF4mbebf4jMUirb8yeloe1si
         4thukdrSySoWan+ESW1mQVHmMXNHfmqTKU0Doj1afLaMz3Umhjhm+uDuhgldoa/MHkK5
         5RVv7OEqRu5MuWCIZzLU0FTSIf7c1bkq9x1cA23ehVFbXQ1J9idvP/ATA/5LEp/loeXU
         lbwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UHUyPaQW;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724169764; x=1724774564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sy5YCduC3Zm5zgSYXYt1SmLRrlSVWk08UkmeBPH8HG4=;
        b=EBhEVJzyx0cuJjfJ++5sbW4awOLffEMOCBPX7JVLchFmU5K/X8r2/OFTPbcUZtiqqM
         0pb+gIbkztK7OdqF1SdKcqorsUjTnIb2wr4tQfwnveVGbzXx1Cf0qbKMK81c4vcaMs95
         YVXk+oFGdFQVseCXsNduw1lZBn+TsnZN7EEPORDlCI2xy7JurI5428GtwF2PtiumFkhO
         aLnNSbDrM3KtBkuNk8QvIDLHruldJ2Le4gBWiGRu7FjGoXMQGsaxZstmUTNDnycVnVPd
         lx9gbVZihV31aCku7ENwehq00LXzinipGfEvhD5s22X+zGP6rmRcojpWIu8LSj3iPNNE
         xRpg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724169764; x=1724774564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=sy5YCduC3Zm5zgSYXYt1SmLRrlSVWk08UkmeBPH8HG4=;
        b=FzRgAtbNtifrexOmUigs0cVB1KbSh6KW6TJhg6RRmZkAG7uwuQCYfy+GSyGeNLQNT7
         wh6oswvTwH7uyC9dXqt4yJpZT91ruBUuBblhOEnsaTnKjYp8Bh3bVF+HvPErOAfL0FuL
         6HFJr9agHAIG35bQ1Q8NT26fiV4xfpE7TPnbMbUyEtZ5ePil90uMtpBRYCk6U53ojblt
         JIRilcLRjAdAmoDycsJOhLJ3iPU3N8eRTv92EbeeeOGPw/QvU7tX2ylYV1GRYg68gvGh
         yG6kvFHqEUdifaJ5z2FVcmv77equezz4aXJPDB5qfh6BrYRykuFvopm2CzU439G+8X7P
         3stg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724169764; x=1724774564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sy5YCduC3Zm5zgSYXYt1SmLRrlSVWk08UkmeBPH8HG4=;
        b=Fs7f2ZkdVvkB2IXpPKjcoMG9ywZwr08427RftJKmWJPGD0R3H/8nYgSOG95KEjMwQW
         x0jVZ0Y7g+eWQ12l3Kjs8cjpKlJfiXAqNONiKmWWGUBqeypSdhQ6zjhzMk4dKEkHEEGt
         o/7oId5ShixsrzcjJwfXuh6MP1CWDsyMtVeGAvLIoTKqPCnTwbZZQz9O0vb8DzdrkOtF
         BgvmywMFKKPftCFVVzs+duTx7miH47oSS4g4HQ9y4JKzg0bvOpd411wR9IBiaDDXZxM2
         +ZXCsHOVi+keBlIASTWtJqH0emImjpKZeEvzto2JRVMOqYsjxNLQDt1kZ6/K1Xtt/F/I
         +gkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVR9zjhGul9UWe7+Wioj0XlB6Rta4m+YFKcMe9hv5355r3WWzk79/G7PRHR/BQtU6vmqfssig==@lfdr.de
X-Gm-Message-State: AOJu0YyFL/3+9AfJsWIQz2LjuwoKNBAC2KP/voxeZ8IzAqhXlyqbTQjG
	EyAMTUTlRyuRacOzK/kji2Iqm6NNVYiH5Q/D1WtL82z7GxleuazU
X-Google-Smtp-Source: AGHT+IHUyEV5mQ3uiIJo8a4kgnQ5ASKGVImx0QRK85l2bzvsxKdfUfBf7RmLzau4odR2c11tyM2hFA==
X-Received: by 2002:a2e:b8d4:0:b0:2f3:f54a:efdb with SMTP id 38308e7fff4ca-2f3f54af07dmr4512851fa.17.1724169763401;
        Tue, 20 Aug 2024 09:02:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a05:0:b0:2f3:f220:27fc with SMTP id 38308e7fff4ca-2f3f2202940ls558801fa.1.-pod-prod-02-eu;
 Tue, 20 Aug 2024 09:02:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWuI9um8E5X3GMpZ8IY98we9MSxAcgAK3VEy1uiXL9eH9rOg7N/nK6Q415aHD332yd5DKyfngQ60Y=@googlegroups.com
X-Received: by 2002:a2e:f0a:0:b0:2f3:cd89:c722 with SMTP id 38308e7fff4ca-2f3cd89c83cmr61782551fa.33.1724169761231;
        Tue, 20 Aug 2024 09:02:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724169761; cv=none;
        d=google.com; s=arc-20160816;
        b=hNZ00H9OtmycX4gqokh/r/Dz1edPH7NwjT4uBUXCVqNdwhkim6J2jLP36zMPFkvqPP
         mL9dBjVq2XFzltDmWMp6EPtxq6+3/RxtZ6l3Ay8R3qcDsuzZcbrwwSGq6LbDhvB558Yc
         ehiMn+NGbiWnMs/AqQReBbfTHgyjMSye3JE7IluMHdCczgwEyZnkugPDlGMSqkGJ+pPX
         T98it025iLmj34l4/Q9K5zqKpwvOmhEaoD8QKERnAn1GKawDzZAVi9o9/EGMaYP2Qy7N
         fTnHpDsyOGe9Fy2DO3A68xEhIbwYC9A3qVSlTvHu3DPZ0U6L18kJZaiaykO0pkoPSeoz
         axUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=H6SCEVIACYGUuKiOlfM8plsiG93dGJNmKrdwRKLr5bQ=;
        fh=plHpjJmSqjgkGXKnYKjTyUn/pvZbgcH3GTOBRiaGpDk=;
        b=LaV6c8UttLEOb2cyXw8MWGNYbXTGscI7H2YRAPwavoW/+NuPkISiQ1i24bAwv552rR
         z94uxL/1HEPbhtT9JcMp1IQ1pQtP27YsKSkYlI/iOUSdnnpGTIl/lWO4k1+HssIACdS0
         JK7Rj7hrpGBkOvSOky4SWuduDr8i6m+hltZyQi3qDqM0UCZETYf2At4b0uq0ccJAV5xd
         h5r8Xt/0LaZ+28t1+nElO1Fyb2bo5+52ihrOJcjzqmA3CPZNnd/e93Zf5Q5/X+ByC/vr
         EKcEtdZSPCSfMsa1hBwpqW5SZhq1RTCLwXx3cEpZqXcIaaFmod9apbCUGlv5R5fNg5ct
         b4TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UHUyPaQW;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f3f31537dasi164221fa.6.2024.08.20.09.02.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 09:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-52f01b8738dso4752426e87.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 09:02:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUAUyX+61l/8vZAEAYOnc3aB2Kreg8gy5orA8Rx93zLaX+LmS7fj5zs4vBY0gQBswQpYnVdkyv7ow=@googlegroups.com
X-Received: by 2002:a05:6512:3085:b0:533:809:a970 with SMTP id 2adb3069b0e04-5331c6a20e1mr9584254e87.14.1724169760015;
        Tue, 20 Aug 2024 09:02:40 -0700 (PDT)
Received: from pc636 (host-90-233-193-131.mobileonline.telia.com. [90.233.193.131])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5330d3afd26sm1814968e87.12.2024.08.20.09.02.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Aug 2024 09:02:38 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 20 Aug 2024 18:02:34 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>
Subject: Re: [PATCH v2 5/7] rcu/kvfree: Add kvfree_rcu_barrier() API
Message-ID: <ZsS-GiHF8QZ929Vn@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c@suse.cz>
 <ZrZDPLN9CRvRrbMy@pc636>
 <6a6c1c59-eee3-4263-9cad-53b57d78c018@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6a6c1c59-eee3-4263-9cad-53b57d78c018@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UHUyPaQW;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello, Vlastimil!

> On 8/9/24 18:26, Uladzislau Rezki wrote:
> > Hello, Vlastimil!
> > I need to send out a v2. What is a best way? Please let me know. I have not
> > checked where this series already landed.
> 
> Hi,
> 
> you can just send it separately based on v6.11-rc2, as you did v1 and I will
> replace it in the slab/for-next. Thanks!
> 
Sorry for delay. I had a vacation last week. Just posted the v2 with a fix.
Now my tests are passed!

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZsS-GiHF8QZ929Vn%40pc636.
