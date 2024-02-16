Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2GDXSXAMGQEER2ASGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4488577F5
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:50:49 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-511559b30edsf1203411e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:50:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708073449; cv=pass;
        d=google.com; s=arc-20160816;
        b=k15/OCZFcr5ehLwckBmr4dcb0Nr6lvEkK2f64nA5ocTyY3KuJd7esbwwBnUKLzWp4g
         HTLiOzM6bcWot7/wT6W7LP9yuCDlRvPKMYdWbVs70uOVVEx1gzdBJoh2w5vyRJTCbK2J
         soJVL+JEKT5zsx+TTUPovCEemgdnWTVX5skgVDDLRtXjt4/UYzwkzbKCOImGp3X7tmG2
         m2B0Apm6DQl14gKlrRTbhlEvVMxkZw8MRuVWzz49U1XyViLAjlJNVlbdxKCPu5P4gl5J
         rsAEvQSwX2VmRP6fve49qsGbfA46jxRGw8+C19I2oXBYGG6M+8Ynr102NnZPbu/e2Yoz
         mxUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=7fl5wtuBHQJ9M9JMkUXwWYErZnk3fl9SYrcBUwJGR0Y=;
        fh=7v6zfvCddNK+p1n2NdePYIm+6wK0bL0wHnIJ+kLpSKs=;
        b=Qeakt3TQub0DOevNWaUyjkzGHGvALX3fZo3CNkGtgAOD1FORY90n5Y+1+371pkAmxd
         8Upuxg+wizCkdy3U21YthzWS6xnotKo1CSuGK+3HxQuYL5WxW5rjfk//07eq4ILNClpm
         +x8fiVoZDX2z3ztg2XMnJ82gRPMx1J5N3kG/ychwrGxRxUAyjfWLVpd2FbQZzQjsxhs7
         kFtJZs6AQVc+qSG/kFKm0NhohqRizEO733MayimPAF1YCZL3GEX/jJd4/FsfvaDML72Q
         iqj9AFlWDFGx3KwWwvcyJHtjE/x2wybmhz2eK8CXsAwLyOldxCcF25QIIlA/iZC92DH/
         NsSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yA/4iNTU";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MsHa2qgD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708073449; x=1708678249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7fl5wtuBHQJ9M9JMkUXwWYErZnk3fl9SYrcBUwJGR0Y=;
        b=KMKeCYXPJhYT31WKLHQrTRri031QN0h5MTYgnOMdD1FbnSB+LgyZm0nuE1NeFnOrsq
         7tr5CThLpt+uEi+Jj51zoMZDT7eR2CyNSI0yomGYqmmRt0gXaUscWP0KsGsAjAgyiOVJ
         /6OMKDwB049+bgjIpoIkiYRkCNYtg8+WZHI/rRnGRNRaERbUZRc7yqQDr/Z830Pn+sWl
         7pym1AtOH2jNrIYhot8+niAEqSs6o46SKvTKeN7HsLMLVVp/jL+8sXT3wnqbQ4xY8lhb
         GdRJyiYxY6/nXmV1kXYdVakllTJsdqBckArEj6grCLsQR9PYDIXBSPVnw+eV+SD2HzKT
         dX1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708073449; x=1708678249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7fl5wtuBHQJ9M9JMkUXwWYErZnk3fl9SYrcBUwJGR0Y=;
        b=oD002Gior0u4V1jCqFj5IrbtV7px+Kp/z+eKGtkgQkf25/mVlgX+4r+6si9Fw9Nm3O
         xDSaIFFabCYKGlfSJeUN55AaaeK6wFarF/6we4p7DVJqC4NV1SezOdHeDQ52TyKoG4m4
         f9vY16udKk5qvfxpk5rtQ07ysgfa2fcEE/Hpr6w7AYXajgUaovt0TXcACaJWG98irgyi
         2VAR56p6aMBou2rXFwHpoDk+QcHnO5d83rSuiVUvhh/mnVxTZkgT1G1VFC+JcYDvz04h
         uJm+CVvIuAoZwBsgFRDHQYKflhCnj17Zitd1VbCFT2DwRpU0jywk8lgPGLNM6gvMZYQl
         1dpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDD/V9qUYuV0ghp0HvgQRhqTsrVY/NvCHQ95W6vOML6Pi6TWuz6+48wayIra5GstWG2fZ9n+adyDqPYhA3UCjpJY+mqCxCpQ==
X-Gm-Message-State: AOJu0YxmQnMfN9dvcAYVnYEm0Ujw5Zbe5uo+Mf9PXQHr8krtuwL42+Tr
	NhOIA8KPOpMOPHfBZc7DEmKN33Pg3+eb8BlvSHLe53VFABDy1lvh
X-Google-Smtp-Source: AGHT+IEAWixMY+WDGe309k6re7qOvn8s+PGdo4ijod9eqWXuEyBRQcXbCx8HXOov0CYi5waTzqTGzw==
X-Received: by 2002:ac2:5b0d:0:b0:511:4b8e:fd13 with SMTP id v13-20020ac25b0d000000b005114b8efd13mr3232183lfn.57.1708073448679;
        Fri, 16 Feb 2024 00:50:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b26:b0:511:7247:5108 with SMTP id
 f38-20020a0565123b2600b0051172475108ls304960lfv.1.-pod-prod-08-eu; Fri, 16
 Feb 2024 00:50:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFWElN+0D/WvUn56Di4QsjFhsCq2GnUIt4aj58RbqH7lWDcSZB7UZP91lcgk7+/BX8Kf7aR1gVSFhnwzKJ80rn+GKkCwmL8Os9Og==
X-Received: by 2002:ac2:44b4:0:b0:511:acdb:67f8 with SMTP id c20-20020ac244b4000000b00511acdb67f8mr2879726lfm.68.1708073446723;
        Fri, 16 Feb 2024 00:50:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708073446; cv=none;
        d=google.com; s=arc-20160816;
        b=URx2WJB0uP84wqmn42hjcDAnE+Eas/xZgf//oL0dcGBr6BSME7yRoXsclpLqPPsn3Y
         cm8JLJ3VDl0PNM/g6Iz61nd8YjTGL1kTOk9wBTWJH3gZbNWVM/4yKBIxwvkls1Yaf0cv
         ZSv7WTKzJ2ogOkmWLesA6qh63wqwUPpI2ReqQQNj3PShYYYJLz4tnRWmMhCtE3X5KXPr
         DqGvk3s/bp/u1jyLsHrcc00EwVjJCwar+/qb1NErvmyCCIO/T6AYeT55Mp0QPFClUivT
         EE2zKO5sxsJVGfAQq315rNJhS5igGAD6QXGDokzAqWEMfWjdptpbmfdm1JoS8pKS1yZM
         ioeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=LvS88A1JZEeIqJIhe88zQYazuSktyNUKiwnG9k26ga0=;
        fh=kRg2yjE/JHxFm2Iv533U9KbGmA9rsbhStUCUHeA0vxo=;
        b=yEujVQxYvd/XAxOsNwrFZVRhtmUoEAfZ019uqjjIFlrpAAZjg3OAbxkykfPPxE6ifi
         w3rrMO8laOWurgWqMhBLbGijibkWtnLrwU8UyWlcenv7ADtlIGDvAjZhAe2O7BHWhC2m
         0FGkJAMyaKT72t0nNHI0BQshGqBbIIsHkMIAwCLhyNaV1A7mdkopi2LfyKuWwED6r8oY
         PO7GQ7DJ/pAxI5OwVfcZysYx0uHmaQgjorIKLYne8C9enxbxX3jqz1Fop4Ory/XUHaNO
         WABzt5N6VZn2KFrsnFn1X+hZt7ftp2r8J0jyJGse2PBdEbMmB9IB6SOTQBv7XnEO4Wl6
         8VDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yA/4iNTU";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MsHa2qgD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id fc13-20020a05600c524d00b0040ff8f0e6acsi49924wmb.0.2024.02.16.00.50.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 00:50:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E87671FB4A;
	Fri, 16 Feb 2024 08:50:43 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5FF7E1398D;
	Fri, 16 Feb 2024 08:50:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Na8jF+Mhz2WqYwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 08:50:43 +0000
Message-ID: <af9eab14-367b-4832-8b78-66ca7e6ab328@suse.cz>
Date: Fri, 16 Feb 2024 09:50:43 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>, Suren Baghdasaryan <surenb@google.com>
Cc: "Darrick J. Wong" <djwong@kernel.org>, akpm@linux-foundation.org,
 kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
 <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
 <20240213222859.GE6184@frogsfrogsfrogs>
 <CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
 <202402131436.2CA91AE@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202402131436.2CA91AE@keescook>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-1.80 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[chromium.org:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[kernel.org,linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: E87671FB4A
X-Spam-Level: 
X-Spam-Score: -1.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="yA/4iNTU";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MsHa2qgD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/13/24 23:38, Kees Cook wrote:
> On Tue, Feb 13, 2024 at 02:35:29PM -0800, Suren Baghdasaryan wrote:
>> On Tue, Feb 13, 2024 at 2:29=E2=80=AFPM Darrick J. Wong <djwong@kernel.o=
rg> wrote:
>> >
>> > On Mon, Feb 12, 2024 at 05:01:19PM -0800, Suren Baghdasaryan wrote:
>> > > On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromium=
.org> wrote:
>> > > >
>> > > > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote=
:
>> > > > > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions =
to easily
>> > > > > instrument memory allocators. It registers an "alloc_tags" codet=
ag type
>> > > > > with /proc/allocinfo interface to output allocation tag informat=
ion when
>> > > >
>> > > > Please don't add anything new to the top-level /proc directory. Th=
is
>> > > > should likely live in /sys.
>> > >
>> > > Ack. I'll find a more appropriate place for it then.
>> > > It just seemed like such generic information which would belong next
>> > > to meminfo/zoneinfo and such...
>> >
>> > Save yourself a cycle of "rework the whole fs interface only to have
>> > someone else tell you no" and put it in debugfs, not sysfs.  Wrangling
>> > with debugfs is easier than all the macro-happy sysfs stuff; you don't
>> > have to integrate with the "device" model; and there is no 'one value
>> > per file' rule.
>>=20
>> Thanks for the input. This file used to be in debugfs but reviewers
>> felt it belonged in /proc if it's to be used in production
>> environments. Some distros (like Android) disable debugfs in
>> production.
>=20
> FWIW, I agree debugfs is not right. If others feel it's right in /proc,
> I certainly won't NAK -- it's just been that we've traditionally been
> trying to avoid continuing to pollute the top-level /proc and instead
> associate new things with something in /sys.

Sysfs is really a "one value per file" thing though. /proc might be ok for =
a
single overview file.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/af9eab14-367b-4832-8b78-66ca7e6ab328%40suse.cz.
