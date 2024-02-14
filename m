Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3NHWKXAMGQE4G265YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D6998546FD
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 11:20:31 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4106fd0827asf8696035e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 02:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707906030; cv=pass;
        d=google.com; s=arc-20160816;
        b=QsijFJCi8KATaVQGs+3zvqU3SJuFwRHEdnXlem+PvI080K6FeZnYf0tLJ/d5/Gdj5f
         WRNOign/+ZnEjPUU07VXygS3cccrFzrWYVmwVZ+wJu+0TSOPnPisqoqV5uR3L4UyStmY
         UN7FCRLQR/j5wQXlS0m2KsRol4qGm+JdbMg461bxPXE4MZ38MA25K9lKe2JpCJBZDmpy
         wMdYXLQ9KiY+l9afcmfi7/4ywxQQ2LWBBvRQkZMQ3xocwI8ulzhtGrYpZo6y8cy7shKm
         fXOkmH4ybfSN1nY+XH5SZ7BKbbI8AzVrkeHf0PBp7KzuHODLeTL8WVRCUwmsWo6K0Fe0
         babA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=RWA1F9HnxklbjBXxqk7aLUcOI6q7C1EnI+jQejS0mYQ=;
        fh=+3fkp9WURCYx5GgXxTZQ6TbknhKAzNunpcCItSTZ/IQ=;
        b=QvsUk3wLHh1k1tdmJJPzYVRXBUav2Qvykj5VkWS1Ly86G2Nmnxmx/ZM5p/448cGbF6
         +Vnoz189u1PF0cezzu+NLo0H+4TyJHk3eQBNDyQysjjqLNfgVOJ01eN9XpNrJ/N+OSR6
         xnBwy1CS/piemmXxeXkRhm5T0r/6ddljiFpkU3m8jVHLkFc3CgOkynOGnC7jIlvGUxub
         PDG9puvLbkwEbOU02wc3ua2kqUSRwummOnw2nUgesmgE+NSbFnblVMo743rCChvJnAtq
         JqO/9LgDi0l59B3MMxoYp30xuBS7g8KJjFFVJjTKAf1WiiuGLNLLcuzCIsL5uVXBVOCH
         97Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707906030; x=1708510830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RWA1F9HnxklbjBXxqk7aLUcOI6q7C1EnI+jQejS0mYQ=;
        b=wA4GQ/9SWiGGc8M9xVIBhjpA1zpk0mY7YzkUTaNn7JNkVS3k6vo2xVAXw8jVOlo2Rt
         LJUTY1uwQvhBfxMcREQNh2yw3YqYcmbGmot9CL/ti+w1JrS1ObFGxTALO5//Jo2t7qbC
         mpWwx+Wit/f7W6Mxm88CMyzNgyaqYSt2jpBZ+dTf1zwwNnoh6iZwWzF+U70Zh/UIBZL3
         8Q7J7sbR416N3xw2aNqxupLZ6bUHmm1tt1LhSrmIqLP23aVRF252BH+4gy6zCOV70p5J
         Ud0AzM0kh4/evxjn4ZvNkgFOrLzy7SLofbcOb2opb2q9Y3Fp2fnyOOf8dX8JYTWdohkv
         vcVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707906030; x=1708510830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RWA1F9HnxklbjBXxqk7aLUcOI6q7C1EnI+jQejS0mYQ=;
        b=u7LVl9rJqZ9soYyLonOXz+0PQqqEvB5P9zpKpfQdSMsA4s3Px6pr0I23kj3CViKfPy
         szG4PM0MTRzFb5o2NJGFP0D55bzk2wP0viTZouISGyRgqKQzmN99xNn9zja91s6jHhop
         CSQXfQPFRnDkxB58/BJMlSL7HebHYDowSbGRR2HBpY95w1cllMTfovc10luXJstROeMZ
         xcZnxzHaav8Dvma3rcM+FeOl1OBJPNZX5KbfDj0gIMDToFDlidQt96/tkut5KF9+/YAG
         7/DjvLZDOMu0PRqgeCsR9wmuRGaylrjYPd7/zjPAREBvEskc17kv8JzqdDw8He3OI5cb
         dpWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzqvWZSN2gdDRqwOXkFzroTPk/sR2uRo22pTILvN2p0kynsdlAwuGQ3Uqbl8BWBQyZyKIFF3L29wQXkDbw1zythVTRs1gZsw==
X-Gm-Message-State: AOJu0YwivR3t/iSpI+SDxeXMry8hAaOj9PM/sIESJcJ8BBC8LVXEqLPw
	jOpqcJpG0dokEFdAvZyO/A/UXQRPPDSs0+GKEcW7qGEimOl/KuzC
X-Google-Smtp-Source: AGHT+IGDuMYj+z+LEo2AKPaAS3EJVIDWszHnmUHFBakJ/rm/OdBs4kFjCRBcHCX4NEcIBb0GOtPr4Q==
X-Received: by 2002:a05:600c:1d1f:b0:40e:fb76:5344 with SMTP id l31-20020a05600c1d1f00b0040efb765344mr1794974wms.11.1707906029977;
        Wed, 14 Feb 2024 02:20:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f0d:b0:411:f44c:67f5 with SMTP id
 bd13-20020a05600c1f0d00b00411f44c67f5ls115555wmb.2.-pod-prod-02-eu; Wed, 14
 Feb 2024 02:20:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRoRCuob8hCXaaFC6pLMMe6V8wR/O3qvPo9n74/L2b92EPqf+/Q1iSfArDttOZZaxp3Y6arzQTlKJnYkGNbtYQbyK1m0g4qCSyVQ==
X-Received: by 2002:adf:ea8a:0:b0:33b:627c:9d0e with SMTP id s10-20020adfea8a000000b0033b627c9d0emr1400786wrm.53.1707906027915;
        Wed, 14 Feb 2024 02:20:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707906027; cv=none;
        d=google.com; s=arc-20160816;
        b=MpQwgDBV0bvNWG3WHokOpcdQAs5fG34mHb6/vIKWYsV3qXZEFVYBcyqG8rTUhRmFjv
         RSnBCVkI9yzziQAwXLp46ddq5Uj3oRGwGBQal+RQenMuTIreqJ29XUsvvFhec7Y2yAZe
         SoyH3/pJTTgvX9fN/hzggN9TYYxTigvB1g/YNOymDa/L61Amxhd9AL+ko38vLC8K0jq7
         FJsHngzfggBLolpi9nZuVjNTnSUttPJG96TK1pXv3SzPAVvDtzFkEq14h8kXneUMZg3x
         uOfg+gCyA79lTHLbGcu5lhbtnf50avHTfBb0VwAqBc0D/RlzJF+AxSnZQAPFVUo2PWLr
         OzNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=FGladMXENrd0YjrbTrjIK8mVP0LFAbru1yEEbY+cSOQ=;
        fh=ADSooXYCY+dEsy54ADiHYYczo4POV8C6S3JYJjNhkuk=;
        b=iGPEXEUuL58Ems+WApjxssu4LGcRXYT7vsMwJRzZFubs9XHO5IO3MGzyapwbmGWE/h
         X08ak824a8DAfhzgOobdIDbyM7WH3UDRJo9qVpf1oVvfHM7Xo0MMdw2VFWh6a30z2nTx
         RZfyGrSfe1hyEr0oVrkeliouzozYzUtAR5YYQSYz657kXx8k8ftqYpN3csHlB/+Trd6b
         0C9Y5qRHjAZ7uZrv4z+cNImRFXqosR+P/XCzRuxA3T2zsflZDNhlm7hnTU+APfv7c6Py
         BLVKfSnX3qw3neV5tuH0s1LD6dM5K7H9Kt4udJ1Njc0urxubLj7/PSBOwiDKZ6fZv0OA
         JQ5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
X-Forwarded-Encrypted: i=1; AJvYcCVhqy4CICeNYbebpHaWOx4v7Z9+Vd6KlSAyukhpU7BbAUjcNyT2ukq0aRpBXNhKtKXCJqoiv7w3rIB3+g6sdfA6AfW7I2l4TzYO6w==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id g13-20020a5d488d000000b0033b1ad6701esi629820wrq.7.2024.02.14.02.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 02:20:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0DC071F7F2;
	Wed, 14 Feb 2024 10:20:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7241913A72;
	Wed, 14 Feb 2024 10:20:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wRKNG+qTzGW7RwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Feb 2024 10:20:26 +0000
Message-ID: <4bb7b1e4-d107-4708-bb65-ac44d4af9959@suse.cz>
Date: Wed, 14 Feb 2024 11:20:26 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>,
 Suren Baghdasaryan <surenb@google.com>
Cc: David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
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
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-1.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 MX_GOOD(-0.01)[];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[redhat.com,suse.com,linux-foundation.org,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 0DC071F7F2
X-Spam-Level: 
X-Spam-Score: -1.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DNRgpeGh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
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

On 2/14/24 00:08, Kent Overstreet wrote:
> On Tue, Feb 13, 2024 at 02:59:11PM -0800, Suren Baghdasaryan wrote:
>> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
>> <kent.overstreet@linux.dev> wrote:
>> >
>> > On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
>> > > On 13.02.24 23:30, Suren Baghdasaryan wrote:
>> > > > On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@r=
edhat.com> wrote:
>> > > If you think you can easily achieve what Michal requested without al=
l that,
>> > > good.
>> >
>> > He requested something?
>>=20
>> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
>> possible until the compiler feature is developed and deployed. And it
>> still would require changes to the headers, so don't think it's worth
>> delaying the feature for years.
>=20
> Hang on, let's look at the actual code.
>=20
> This is what instrumenting an allocation function looks like:
>=20
> #define krealloc_array(...)                     alloc_hooks(krealloc_arra=
y_noprof(__VA_ARGS__))
>=20
> IOW, we have to:
>  - rename krealloc_array to krealloc_array_noprof
>  - replace krealloc_array with a one wrapper macro call
>=20
> Is this really all we're getting worked up over?
>=20
> The renaming we need regardless, because the thing that makes this
> approach efficient enough to run in production is that we account at
> _one_ point in the callstack, we don't save entire backtraces.
>=20
> And thus we need to explicitly annotate which one that is; which means
> we need _noprof() versions of functions for when the accounting is done
> by an outer wraper (e.g. mempool).
>=20
> And, as I keep saying: that alloc_hooks() macro will also get us _per
> callsite fault injection points_, and we really need that because - if
> you guys have been paying attention to other threads - whenever moving
> more stuff to PF_MEMALLOC_* flags comes up (including adding
> PF_MEMALLOC_NORECLAIM), the issue of small allocations not failing and
> not being testable keeps coming up.

How exactly do you envision the fault injection to help here? The proposals
are about scoping via a process flag, and the process may then call just
about anything under that scope. So if our tool is per callsite fault
injection points, how do we know which callsites to enable to focus the
fault injection on the particular scope?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4bb7b1e4-d107-4708-bb65-ac44d4af9959%40suse.cz.
