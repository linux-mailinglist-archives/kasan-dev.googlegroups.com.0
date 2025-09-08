Return-Path: <kasan-dev+bncBDQ2L75W5QGBBS7G7PCQMGQESCDDU4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EDD8B492BB
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:16:31 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-3276af4de80sf7375810a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344588; cv=pass;
        d=google.com; s=arc-20240605;
        b=cjH42V3zUDp+04G2mm+LJaIVK2t6aorKxbYvCe1++YkyF2PlD+1laa2ogSALo3aKqF
         JR7lC8dQQoFaGjBKp+LqYhYlgU2hUcdLiZ3CvW/hZIEdBcK2AMaZM6f3PNTWeAk8GZEs
         F6LOT/SjqqlriD2CZGSJ3NkCy9+Jym0/7LUGsFJkgOigqQMtemdGiGJe0x1m8aCnLWU8
         HcNC54i7npYnIuIrXyNok1H0GhTRBrI7OD5loo1CK8jtzjrkqRJdy4sqJUwFhYQjWmB5
         4ySNJPnFLPgkZyluF3aizh/ub3vzbuoTsMqZL3FxJD9yeGhJTE/xH6zqg/AXhsAOJA37
         BYYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dj6bciF0hYvPrnPUqfIt03ult9jIPfcwCocUFUU8QC4=;
        fh=sUSNbU4pft0cizy/PZ60hn4YjZVFcV4JSnGrxqaorw8=;
        b=hGsieYhV3P6SwbelT48MPBQlw0/HpFfEuTb3fRQ8VdHXjMlNl/tszXIGbdglJxs06/
         IF0gyDOCK8gF0SFLIKwf7H+iok+itbtqqpEKLGgehhi89RVEK+k2oGpthOsu34+lsRdJ
         D4mfISz13kfX9FgGeo4tdwbfkwv7TtWQHbGUtsvuNUuaMETwhu+d2cMoBM2k5mKoU0VV
         4mpphWjt4PNv3L5l15fXzZyHNTCxNVVLiND4ywGESpTP6B2uvUdQNMa9F5OpnFM2brIx
         Xr1r2zZP6bcWKoBQfDzwceu/xQT39Jr2gIPGXsuBIAY2rPRbqf57UttgfEO/9uzQdckG
         AioA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xt4oq4p+;
       spf=pass (google.com: domain of broonie@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344588; x=1757949388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dj6bciF0hYvPrnPUqfIt03ult9jIPfcwCocUFUU8QC4=;
        b=OtEfu569WJZASAH7yV6++XrU1oO70pd5oh64hep9gR+8BdsHnejQJJWtTlmQK5LY36
         qvZQEkcWBMJ5ehTEuWjMP/r3K9GqYOy+bj9rcqrd7SjdahxXQ9gXQ9T3m/CMOmUc3maS
         5NnqfE6P458pv8JEH83Yzqlmqfd8yeQYTegxrU/ct5AWdmrFW4K6izfo91VF7PPwTkuT
         kB+/AoH8QCOWHS2b0KetWEo9Sgqx6QsiyQX2LAXwUGyU8kNvF3Li/x8eAZxmWlfOzTVE
         patatvKwrmu0+j4jbOJjcjVBvEl+5j9+P8UZ6WFALaMXkngTloHBhh8HIgruEWt/CBje
         4cxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344588; x=1757949388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dj6bciF0hYvPrnPUqfIt03ult9jIPfcwCocUFUU8QC4=;
        b=Nf/mL865+b+CJm2Hqwtqstgb8sOrHJtcAXWIQdHQ9/rk8S+QUt1bxxlIKgaYoG6Ba0
         IhB/Z6+N3G/efg4ck19p9oKNXNjJHQ/7EeHYH7k0oLfGd0tKLO6agd+UdiCliVr0MBpN
         3Wjlo1gqv6xt0fElNcUXskruxPAl9PeTqTnPZ7r8QPtsw+AKvE99Yx65GTXiKtyBn7nc
         acfG7mBeQq+0DR4BeIXrbUK4me5Yz5R9hP/V7kvWuAs7rokHZuuaUCL2/FX45/g3D5ey
         MYZRfCZMYSffGKTbJCJiXHB9/PckPSsA2tJ7A+ev6eT6bhMlBkMt874FfTUNYZOAcp7/
         G9sw==
X-Forwarded-Encrypted: i=2; AJvYcCVgtn30A5bezAOUjVOHGdlVoprKsn4WSEbjZRZfmsJoiFbwYTf3sWeQJiWiZCxNLfdIY+0qGw==@lfdr.de
X-Gm-Message-State: AOJu0YxBXjisxxupC/Jmw23Nwtlfht8b+C/AfOFUBPu7oKgPC9KOgJ5c
	PITB7vhE8Zm8ziM55nE1c9E2vRz4XP2cQ2ih315eB8kRwVcGdUoDJnRO
X-Google-Smtp-Source: AGHT+IFfJdXnjkZ8DrKr57D2TroC4ZQ1Jec6kcVax6LglTxHAoZ+/hWJewJah5jEmXH+Okei9Y9f3g==
X-Received: by 2002:a17:90b:1ccc:b0:32d:90c7:c63b with SMTP id 98e67ed59e1d1-32d90c7c6e3mr3277419a91.30.1757344588019;
        Mon, 08 Sep 2025 08:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7ts5mfkzBxA1pqYs3C8l/Xq4hzgHvfLgb7alYguoyXig==
Received: by 2002:a17:90b:14c9:b0:32b:aeb8:1dde with SMTP id
 98e67ed59e1d1-32bcaa090a0ls2276708a91.1.-pod-prod-06-us; Mon, 08 Sep 2025
 08:16:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgP04SJNuvkF/2UiesuECs85I9QB12Ma3ktqdomwtxhxFWEVEshRCWD9jOyZG7laE23TDhSPjFJz4=@googlegroups.com
X-Received: by 2002:a17:90b:35c6:b0:32b:a76d:4c56 with SMTP id 98e67ed59e1d1-32d43f93f21mr10452679a91.31.1757344585887;
        Mon, 08 Sep 2025 08:16:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344585; cv=none;
        d=google.com; s=arc-20240605;
        b=ZwNulSEND8nT8oyEPx0sQBEU5v2XWiUgOxh4Ym4Ea75xW+h228ex/mQEzIYcEJ/40W
         1IxOzaVM/0aKlKn6lkDLFcBR3txvewo67v/KPU20FMyGwzgF1YZmeL0452gmu92j2bF2
         2HdGt+A+UVht6Q6vDbAT3wkMqkpkm4RZ1Kxux7UWaUPPnciLBmYf1M6b4KCx79kxcRyU
         9iFIiQfpydLoCmJ+TVDNkJ9txjdQAkBThxZih/NZu64oOdsEnFSxneq/IcRG8i2gwhF7
         uSszUMapuoaN/ZJ64lzmxwE8KfjRFFN9GGs7Y3DZLMU7qrvAxlLYkiNXRQDR6b2i1k5S
         KTig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uaHFbhx/XBlASUnOZAQdy0Z2tl616U5pSf55LoX6GY0=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=cN1sMHuCchFtYJi7h+XWFP7jAGZCTksPKoySH8QH3rsgd75hyrytXZJt/0ub7DOUmJ
         MzPy+U7rp6J9ACk3tx96Db/leD2ApV80PUuvjFwvI1MiK08abhP/w2RQr/R/e7DR1q1U
         RuSeUU3bGav5myrjA1fDVBTa67+mLQCim4/5hQ93k3UZDdGj8wWImA5t3HzS9HoUj1Qv
         zL/y7XAtPALWXpcDCpEp8NHG4XXEHH1iuLP1tn2hth++A7ZXsmrBADqTAai1G7egVPQZ
         z/h2b01e/uzc2AQwaZ6Th/FW7OJP33KTLnSHabf+l0JOJ4Xavruxn3508UiXBec5wl32
         dNPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xt4oq4p+;
       spf=pass (google.com: domain of broonie@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329e729b3f3si748417a91.1.2025.09.08.08.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7DEBD40687;
	Mon,  8 Sep 2025 15:16:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 88CCDC4CEF1;
	Mon,  8 Sep 2025 15:16:16 +0000 (UTC)
Date: Mon, 8 Sep 2025 16:16:13 +0100
From: "'Mark Brown' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
Message-ID: <f5032553-9ec0-494c-8689-0e3a6a73853c@sirena.org.uk>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="V80dSr/3LzMwjpsi"
Content-Disposition: inline
In-Reply-To: <20250901150359.867252-20-david@redhat.com>
X-Cookie: Trouble always comes at the wrong time.
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Xt4oq4p+;       spf=pass
 (google.com: domain of broonie@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mark Brown <broonie@kernel.org>
Reply-To: Mark Brown <broonie@kernel.org>
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


--V80dSr/3LzMwjpsi
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Mon, Sep 01, 2025 at 05:03:40PM +0200, David Hildenbrand wrote:
> We can just cleanup the code by calculating the #refs earlier,
> so we can just inline what remains of record_subpages().
>=20
> Calculate the number of references/pages ahead of times, and record them
> only once all our tests passed.

I'm seeing failures in kselftest-mm in -next on at least Raspberry Pi 4
and Orion O6 which bisect to this patch.  I'm seeing a NULL pointer
dereference during the GUP test (which isn't actually doing anything as
I'm just using a standard defconfig rather than one with the mm
fragment):

# # # [RUN] R/O longterm GUP-fast pin in MAP_SHARED file mapping .[   92.20=
9804] Unable to handle kernel NULL pointer dereference at virtual address 0=
000000000000008

...

[   92.443816] Call trace:
[   92.446284]  io_check_coalesce_buffer+0xd4/0x160 (P)
[   92.451306]  io_sqe_buffers_register+0x1b0/0x22c
[   92.455976]  __arm64_sys_io_uring_register+0x330/0xe74
[   92.461176]  invoke_syscall+0x48/0x104
[   92.464966]  el0_svc_common.constprop.0+0x40/0xe0

Full log:

  https://lava.sirena.org.uk/scheduler/job/1778528#L1985

The bisect looks to converge reasonably clearly, I didn't make much more
effort to diagnose:

# bad: [be5d4872e528796df9d7425f2bd9b3893eb3a42c] Add linux-next specific f=
iles for 20250905
# good: [5fe42852269dc659c8d511864410bd5cf3393e91] Merge branch 'for-linux-=
next-fixes' of https://gitlab.freedesktop.org/drm/misc/kernel.git
# good: [0ccc1eeda155c947d88ef053e0b54e434e218ee2] ASoC: dt-bindings: wlf,w=
m8960: Document routing strings (pin names)
# good: [7748328c2fd82efed24257b2bfd796eb1fa1d09b] ASoC: dt-bindings: qcom,=
lpass-va-macro: Update bindings for clocks to support ADSP
# good: [dd7ae5b8b3c291c0206f127a564ae1e316705ca0] ASoC: cs42l43: Shutdown =
jack detection on suspend
# good: [ce1a46b2d6a8465a86f7a6f71beb4c6de83bce5c] ASoC: codecs: lpass-wsa-=
macro: add Codev version 2.9
# good: [ce57b718006a069226b5e5d3afe7969acd59154e] ASoC: Intel: avs: ssm456=
7: Adjust platform name
# good: [94b39cb3ad6db935b585988b36378884199cd5fc] spi: mxs: fix "transfere=
d"->"transferred"
# good: [5cc49b5a36b32a2dba41441ea13b93fb5ea21cfd] spi: spi-fsl-dspi: Repor=
t FIFO overflows as errors
# good: [3279052eab235bfb7130b1fabc74029c2260ed8d] ASoC: SOF: ipc4-topology=
: Fix a less than zero check on a u32
# good: [8f57dcf39fd0864f5f3e6701fe885e55f45d0d3a] ASoC: qcom: audioreach: =
convert to cpu endainess type before accessing
# good: [9d35d068fb138160709e04e3ee97fe29a6f8615b] regulator: scmi: Use int=
 type to store negative error codes
# good: [8a9772ec08f87c9e45ab1ad2c8d2b8c1763836eb] ASoC: soc-dapm: rename s=
nd_soc_kcontrol_component() to snd_soc_kcontrol_to_component()
# good: [07752abfa5dbf7cb4d9ce69fa94dc3b12bc597d9] ASoC: SOF: sof-client: I=
ntroduce sof_client_dev_entry structure
# good: [d57d27171c92e9049d5301785fb38de127b28fbf] ASoC: SOF: sof-client-pr=
obes: Add available points_info(), IPC4 only
# good: [f7c41911ad744177d8289820f01009dc93d8f91c] ASoC: SOF: ipc4-topology=
: Add support for float sample type
# good: [3d439e1ec3368fae17db379354bd7a9e568ca0ab] ASoC: sof: ipc4-topology=
: Add support to sched_domain attribute
# good: [5c39bc498f5ff7ef016abf3f16698f3e8db79677] ASoC: SOF: Intel: only d=
etect codecs when HDA DSP probe
# good: [f522da9ab56c96db8703b2ea0f09be7cdc3bffeb] ASoC: doc: Internally li=
nk to Writing an ALSA Driver docs
# good: [f4672dc6e9c07643c8c755856ba8e9eb9ca95d0c] regmap: use int type to =
store negative error codes
# good: [b088b6189a4066b97cef459afd312fd168a76dea] ASoC: mediatek: common: =
Switch to for_each_available_child_of_node_scoped()
# good: [c42e36a488c7e01f833fc9f4814f735b66b2d494] spi: Drop dev_pm_domain_=
detach() call
# good: [a37280daa4d583c7212681c49b285de9464a5200] ASoC: Intel: avs: Allow =
i2s test and non-test boards to coexist
# good: [ff9a7857b7848227788f113d6dc6a72e989084e0] spi: rb4xx: use devm for=
 clk_prepare_enable
# good: [edb5c1f885207d1d74e8a1528e6937e02829ee6e] ASoC: renesas: msiof: st=
art DMAC first
# good: [e2ab5f600bb01d3625d667d97b3eb7538e388336] rust: regulator: use `to=
_result` for error handling
# good: [5b4dcaf851df8c414bfc2ac3bf9c65fc942f3be4] ASoC: amd: acp: Remove (=
explicitly) unused header
# good: [899fb38dd76dd3ede425bbaf8a96d390180a5d1c] regulator: core: Remove =
redundant ternary operators
# good: [11f5c5f9e43e9020bae452232983fe98e7abfce0] ASoC: qcom: use int type=
 to store negative error codes
# good: [a12b74d2bd4724ee1883bc97ec93eac8fafc8d3c] ASoC: tlv320aic32x4: use=
 dev_err_probe() for regulators
# good: [f840737d1746398c2993be34bfdc80bdc19ecae2] ASoC: SOF: imx: Remove t=
he use of dev_err_probe()
# good: [d78e48ebe04e9566f8ecbf51471e80da3adbceeb] ASoC: dt-bindings: Minor=
 whitespace cleanup in example
# good: [96bcb34df55f7fee99795127c796315950c94fed] ASoC: test-component: Us=
e kcalloc() instead of kzalloc()
# good: [c232495d28ca092d0c39b10e35d3d613bd2414ab] ASoC: dt-bindings: omap-=
twl4030: convert to DT schema
# good: [87a877de367d835b527d1086f75727123ef85fc4] KVM: x86: Rename handle_=
fastpath_set_msr_irqoff() to handle_fastpath_wrmsr()
# good: [c26675447faff8c4ddc1dc5d2cd28326b8181aaf] KVM: x86: Zero XSTATE co=
mponents on INIT by iterating over supported features
# good: [ec0be3cdf40b5302248f3fb27a911cc630e8b855] regulator: consumer.rst:=
 document bulk operations
# good: [27848c082ba0b22850fd9fb7b185c015423dcdc7] spi: s3c64xx: Remove the=
 use of dev_err_probe()
# good: [c1dd310f1d76b4b13f1854618087af2513140897] spi: SPISG: Use devm_kca=
lloc() in aml_spisg_clk_init()
# good: [da9881d00153cc6d3917f6b74144b1d41b58338c] ASoC: qcom: audioreach: =
add support for SMECNS module
# good: [cf65182247761f7993737b710afe8c781699356b] ASoC: codecs: wsa883x: H=
andle shared reset GPIO for WSA883x speakers
# good: [2a55135201d5e24b80b7624880ff42eafd8e320c] ASoC: Intel: avs: Stream=
line register-component function names
# good: [550bc517e59347b3b1af7d290eac4fb1411a3d4e] regulator: bd718x7: Use =
kcalloc() instead of kzalloc()
# good: [0056b410355713556d8a10306f82e55b28d33ba8] spi: offload trigger: ad=
i-util-sigma-delta: clean up imports
# good: [daf855f76a1210ceed9541f71ac5dd9be02018a6] ASoC: es8323: enable DAP=
M power widgets for playback DAC
# good: [90179609efa421b1ccc7d8eafbc078bafb25777c] spi: spl022: use min_t()=
 to improve code
# good: [258384d8ce365dddd6c5c15204de8ccd53a7ab0a] ASoC: es8323: enable DAP=
M power widgets for playback DAC and output
# good: [6d068f1ae2a2f713d7f21a9a602e65b3d6b6fc6d] regulator: rt5133: Fix s=
pelling mistake "regualtor" -> "regulator"
# good: [a46e95c81e3a28926ab1904d9f754fef8318074d] ASoC: wl1273: Remove
# good: [48124569bbc6bfda1df3e9ee17b19d559f4b1aa3] spi: remove unneeded 'fa=
st_io' parameter in regmap_config
# good: [37533933bfe92cd5a99ef4743f31dac62ccc8de0] regulator: remove unneed=
ed 'fast_io' parameter in regmap_config
# good: [0e62438e476494a1891a8822b9785bc6e73e9c3f] ASoC: Intel: sst: Remove=
 redundant semicolons
# good: [5c36b86d2bf68fbcad16169983ef7ee8c537db59] regmap: Remove superfluo=
us check for !config in __regmap_init()
# good: [714165e1c4b0d5b8c6d095fe07f65e6e7047aaeb] regulator: rt5133: Add R=
T5133 PMIC regulator Support
# good: [9c45f95222beecd6a284fd1284d54dd7a772cf59] spi: spi-qpic-snand: han=
dle 'use_ecc' parameter of qcom_spi_config_cw_read()
# good: [bab4ab484a6ca170847da9bffe86f1fa90df4bbe] ASoC: dt-bindings: Conve=
rt brcm,bcm2835-i2s to DT schema
# good: [b832b19318534bb4f1673b24d78037fee339c679] spi: loopback-test: Don'=
t use %pK through printk
# good: [8c02c8353460f8630313aef6810f34e134a3c1ee] ASoC: dt-bindings: realt=
ek,alc5623: convert to DT schema
# good: [6b7e2aa50bdaf88cd4c2a5e2059a7bf32d85a8b1] spi: spi-qpic-snand: rem=
ove 'clr*status' members of struct 'qpic_ecc'
# good: [2291a2186305faaf8525d57849d8ba12ad63f5e7] MAINTAINERS: Add entry f=
or FourSemi audio amplifiers
# good: [a54ef14188519a0994d0264f701f5771815fa11e] regulator: dt-bindings: =
Clean-up active-semi,act8945a duplication
# good: [a1d0b0ae65ae3f32597edfbb547f16c75601cd87] spi: spi-qpic-snand: avo=
id double assignment in qcom_spi_probe()
# good: [cf25eb8eae91bcae9b2065d84b0c0ba0f6d9dd34] ASoC: soc-component: unp=
ack snd_soc_component_init_bias_level()
# good: [595b7f155b926460a00776cc581e4dcd01220006] ASoC: Intel: avs: Condit=
ional-path support
# good: [3059067fd3378a5454e7928c08d20bf3ef186760] ASoC: cs48l32: Use PTR_E=
RR_OR_ZERO() to simplify code
# good: [2d86d2585ab929a143d1e6f8963da1499e33bf13] ASoC: pxa: add GPIOLIB_L=
EGACY dependency
# good: [9a200cbdb54349909a42b45379e792e4b39dd223] rust: regulator: impleme=
nt Send and Sync for Regulator<T>
# good: [162e23657e5379f07c6404dbfbf4367cb438ea7d] regulator: pf0900: Add P=
MIC PF0900 support
# good: [886f42ce96e7ce80545704e7168a9c6b60cd6c03] regmap: mmio: Add missin=
g MODULE_DESCRIPTION()
# good: [6684aba0780da9f505c202f27e68ee6d18c0aa66] XArray: Add extra debugg=
ing check to xas_lock and friends
git bisect start 'be5d4872e528796df9d7425f2bd9b3893eb3a42c' '5fe42852269dc6=
59c8d511864410bd5cf3393e91' '0ccc1eeda155c947d88ef053e0b54e434e218ee2' '774=
8328c2fd82efed24257b2bfd796eb1fa1d09b' 'dd7ae5b8b3c291c0206f127a564ae1e3167=
05ca0' 'ce1a46b2d6a8465a86f7a6f71beb4c6de83bce5c' 'ce57b718006a069226b5e5d3=
afe7969acd59154e' '94b39cb3ad6db935b585988b36378884199cd5fc' '5cc49b5a36b32=
a2dba41441ea13b93fb5ea21cfd' '3279052eab235bfb7130b1fabc74029c2260ed8d' '8f=
57dcf39fd0864f5f3e6701fe885e55f45d0d3a' '9d35d068fb138160709e04e3ee97fe29a6=
f8615b' '8a9772ec08f87c9e45ab1ad2c8d2b8c1763836eb' '07752abfa5dbf7cb4d9ce69=
fa94dc3b12bc597d9' 'd57d27171c92e9049d5301785fb38de127b28fbf' 'f7c41911ad74=
4177d8289820f01009dc93d8f91c' '3d439e1ec3368fae17db379354bd7a9e568ca0ab' '5=
c39bc498f5ff7ef016abf3f16698f3e8db79677' 'f522da9ab56c96db8703b2ea0f09be7cd=
c3bffeb' 'f4672dc6e9c07643c8c755856ba8e9eb9ca95d0c' 'b088b6189a4066b97cef45=
9afd312fd168a76dea' 'c42e36a488c7e01f833fc9f4814f735b66b2d494' 'a37280daa4d=
583c7212681c49b285de9464a5200' 'ff9a7857b7848227788f113d6dc6a72e989084e0' '=
edb5c1f885207d1d74e8a1528e6937e02829ee6e' 'e2ab5f600bb01d3625d667d97b3eb753=
8e388336' '5b4dcaf851df8c414bfc2ac3bf9c65fc942f3be4' '899fb38dd76dd3ede425b=
baf8a96d390180a5d1c' '11f5c5f9e43e9020bae452232983fe98e7abfce0' 'a12b74d2bd=
4724ee1883bc97ec93eac8fafc8d3c' 'f840737d1746398c2993be34bfdc80bdc19ecae2' =
'd78e48ebe04e9566f8ecbf51471e80da3adbceeb' '96bcb34df55f7fee99795127c796315=
950c94fed' 'c232495d28ca092d0c39b10e35d3d613bd2414ab' '87a877de367d835b527d=
1086f75727123ef85fc4' 'c26675447faff8c4ddc1dc5d2cd28326b8181aaf' 'ec0be3cdf=
40b5302248f3fb27a911cc630e8b855' '27848c082ba0b22850fd9fb7b185c015423dcdc7'=
 'c1dd310f1d76b4b13f1854618087af2513140897' 'da9881d00153cc6d3917f6b74144b1=
d41b58338c' 'cf65182247761f7993737b710afe8c781699356b' '2a55135201d5e24b80b=
7624880ff42eafd8e320c' '550bc517e59347b3b1af7d290eac4fb1411a3d4e' '0056b410=
355713556d8a10306f82e55b28d33ba8' 'daf855f76a1210ceed9541f71ac5dd9be02018a6=
' '90179609efa421b1ccc7d8eafbc078bafb25777c' '258384d8ce365dddd6c5c15204de8=
ccd53a7ab0a' '6d068f1ae2a2f713d7f21a9a602e65b3d6b6fc6d' 'a46e95c81e3a28926a=
b1904d9f754fef8318074d' '48124569bbc6bfda1df3e9ee17b19d559f4b1aa3' '3753393=
3bfe92cd5a99ef4743f31dac62ccc8de0' '0e62438e476494a1891a8822b9785bc6e73e9c3=
f' '5c36b86d2bf68fbcad16169983ef7ee8c537db59' '714165e1c4b0d5b8c6d095fe07f6=
5e6e7047aaeb' '9c45f95222beecd6a284fd1284d54dd7a772cf59' 'bab4ab484a6ca1708=
47da9bffe86f1fa90df4bbe' 'b832b19318534bb4f1673b24d78037fee339c679' '8c02c8=
353460f8630313aef6810f34e134a3c1ee' '6b7e2aa50bdaf88cd4c2a5e2059a7bf32d85a8=
b1' '2291a2186305faaf8525d57849d8ba12ad63f5e7' 'a54ef14188519a0994d0264f701=
f5771815fa11e' 'a1d0b0ae65ae3f32597edfbb547f16c75601cd87' 'cf25eb8eae91bcae=
9b2065d84b0c0ba0f6d9dd34' '595b7f155b926460a00776cc581e4dcd01220006' '30590=
67fd3378a5454e7928c08d20bf3ef186760' '2d86d2585ab929a143d1e6f8963da1499e33b=
f13' '9a200cbdb54349909a42b45379e792e4b39dd223' '162e23657e5379f07c6404dbfb=
f4367cb438ea7d' '886f42ce96e7ce80545704e7168a9c6b60cd6c03' '6684aba0780da9f=
505c202f27e68ee6d18c0aa66'
# test job: [0ccc1eeda155c947d88ef053e0b54e434e218ee2] https://lava.sirena.=
org.uk/scheduler/job/1773040
# test job: [7748328c2fd82efed24257b2bfd796eb1fa1d09b] https://lava.sirena.=
org.uk/scheduler/job/1773378
# test job: [dd7ae5b8b3c291c0206f127a564ae1e316705ca0] https://lava.sirena.=
org.uk/scheduler/job/1773233
# test job: [ce1a46b2d6a8465a86f7a6f71beb4c6de83bce5c] https://lava.sirena.=
org.uk/scheduler/job/1768983
# test job: [ce57b718006a069226b5e5d3afe7969acd59154e] https://lava.sirena.=
org.uk/scheduler/job/1768713
# test job: [94b39cb3ad6db935b585988b36378884199cd5fc] https://lava.sirena.=
org.uk/scheduler/job/1768603
# test job: [5cc49b5a36b32a2dba41441ea13b93fb5ea21cfd] https://lava.sirena.=
org.uk/scheduler/job/1769293
# test job: [3279052eab235bfb7130b1fabc74029c2260ed8d] https://lava.sirena.=
org.uk/scheduler/job/1762427
# test job: [8f57dcf39fd0864f5f3e6701fe885e55f45d0d3a] https://lava.sirena.=
org.uk/scheduler/job/1760074
# test job: [9d35d068fb138160709e04e3ee97fe29a6f8615b] https://lava.sirena.=
org.uk/scheduler/job/1758673
# test job: [8a9772ec08f87c9e45ab1ad2c8d2b8c1763836eb] https://lava.sirena.=
org.uk/scheduler/job/1758556
# test job: [07752abfa5dbf7cb4d9ce69fa94dc3b12bc597d9] https://lava.sirena.=
org.uk/scheduler/job/1752251
# test job: [d57d27171c92e9049d5301785fb38de127b28fbf] https://lava.sirena.=
org.uk/scheduler/job/1752624
# test job: [f7c41911ad744177d8289820f01009dc93d8f91c] https://lava.sirena.=
org.uk/scheduler/job/1752345
# test job: [3d439e1ec3368fae17db379354bd7a9e568ca0ab] https://lava.sirena.=
org.uk/scheduler/job/1753454
# test job: [5c39bc498f5ff7ef016abf3f16698f3e8db79677] https://lava.sirena.=
org.uk/scheduler/job/1751954
# test job: [f522da9ab56c96db8703b2ea0f09be7cdc3bffeb] https://lava.sirena.=
org.uk/scheduler/job/1751875
# test job: [f4672dc6e9c07643c8c755856ba8e9eb9ca95d0c] https://lava.sirena.=
org.uk/scheduler/job/1747876
# test job: [b088b6189a4066b97cef459afd312fd168a76dea] https://lava.sirena.=
org.uk/scheduler/job/1746202
# test job: [c42e36a488c7e01f833fc9f4814f735b66b2d494] https://lava.sirena.=
org.uk/scheduler/job/1746271
# test job: [a37280daa4d583c7212681c49b285de9464a5200] https://lava.sirena.=
org.uk/scheduler/job/1746918
# test job: [ff9a7857b7848227788f113d6dc6a72e989084e0] https://lava.sirena.=
org.uk/scheduler/job/1746336
# test job: [edb5c1f885207d1d74e8a1528e6937e02829ee6e] https://lava.sirena.=
org.uk/scheduler/job/1746134
# test job: [e2ab5f600bb01d3625d667d97b3eb7538e388336] https://lava.sirena.=
org.uk/scheduler/job/1746607
# test job: [5b4dcaf851df8c414bfc2ac3bf9c65fc942f3be4] https://lava.sirena.=
org.uk/scheduler/job/1747672
# test job: [899fb38dd76dd3ede425bbaf8a96d390180a5d1c] https://lava.sirena.=
org.uk/scheduler/job/1747375
# test job: [11f5c5f9e43e9020bae452232983fe98e7abfce0] https://lava.sirena.=
org.uk/scheduler/job/1747503
# test job: [a12b74d2bd4724ee1883bc97ec93eac8fafc8d3c] https://lava.sirena.=
org.uk/scheduler/job/1734077
# test job: [f840737d1746398c2993be34bfdc80bdc19ecae2] https://lava.sirena.=
org.uk/scheduler/job/1727318
# test job: [d78e48ebe04e9566f8ecbf51471e80da3adbceeb] https://lava.sirena.=
org.uk/scheduler/job/1706175
# test job: [96bcb34df55f7fee99795127c796315950c94fed] https://lava.sirena.=
org.uk/scheduler/job/1699577
# test job: [c232495d28ca092d0c39b10e35d3d613bd2414ab] https://lava.sirena.=
org.uk/scheduler/job/1699507
# test job: [87a877de367d835b527d1086f75727123ef85fc4] https://lava.sirena.=
org.uk/scheduler/job/1697972
# test job: [c26675447faff8c4ddc1dc5d2cd28326b8181aaf] https://lava.sirena.=
org.uk/scheduler/job/1698132
# test job: [ec0be3cdf40b5302248f3fb27a911cc630e8b855] https://lava.sirena.=
org.uk/scheduler/job/1694308
# test job: [27848c082ba0b22850fd9fb7b185c015423dcdc7] https://lava.sirena.=
org.uk/scheduler/job/1693100
# test job: [c1dd310f1d76b4b13f1854618087af2513140897] https://lava.sirena.=
org.uk/scheduler/job/1693035
# test job: [da9881d00153cc6d3917f6b74144b1d41b58338c] https://lava.sirena.=
org.uk/scheduler/job/1693416
# test job: [cf65182247761f7993737b710afe8c781699356b] https://lava.sirena.=
org.uk/scheduler/job/1687562
# test job: [2a55135201d5e24b80b7624880ff42eafd8e320c] https://lava.sirena.=
org.uk/scheduler/job/1685772
# test job: [550bc517e59347b3b1af7d290eac4fb1411a3d4e] https://lava.sirena.=
org.uk/scheduler/job/1685910
# test job: [0056b410355713556d8a10306f82e55b28d33ba8] https://lava.sirena.=
org.uk/scheduler/job/1685649
# test job: [daf855f76a1210ceed9541f71ac5dd9be02018a6] https://lava.sirena.=
org.uk/scheduler/job/1685441
# test job: [90179609efa421b1ccc7d8eafbc078bafb25777c] https://lava.sirena.=
org.uk/scheduler/job/1686081
# test job: [258384d8ce365dddd6c5c15204de8ccd53a7ab0a] https://lava.sirena.=
org.uk/scheduler/job/1673411
# test job: [6d068f1ae2a2f713d7f21a9a602e65b3d6b6fc6d] https://lava.sirena.=
org.uk/scheduler/job/1673133
# test job: [a46e95c81e3a28926ab1904d9f754fef8318074d] https://lava.sirena.=
org.uk/scheduler/job/1673748
# test job: [48124569bbc6bfda1df3e9ee17b19d559f4b1aa3] https://lava.sirena.=
org.uk/scheduler/job/1670184
# test job: [37533933bfe92cd5a99ef4743f31dac62ccc8de0] https://lava.sirena.=
org.uk/scheduler/job/1668977
# test job: [0e62438e476494a1891a8822b9785bc6e73e9c3f] https://lava.sirena.=
org.uk/scheduler/job/1669534
# test job: [5c36b86d2bf68fbcad16169983ef7ee8c537db59] https://lava.sirena.=
org.uk/scheduler/job/1667971
# test job: [714165e1c4b0d5b8c6d095fe07f65e6e7047aaeb] https://lava.sirena.=
org.uk/scheduler/job/1667699
# test job: [9c45f95222beecd6a284fd1284d54dd7a772cf59] https://lava.sirena.=
org.uk/scheduler/job/1667598
# test job: [bab4ab484a6ca170847da9bffe86f1fa90df4bbe] https://lava.sirena.=
org.uk/scheduler/job/1664664
# test job: [b832b19318534bb4f1673b24d78037fee339c679] https://lava.sirena.=
org.uk/scheduler/job/1659213
# test job: [8c02c8353460f8630313aef6810f34e134a3c1ee] https://lava.sirena.=
org.uk/scheduler/job/1659264
# test job: [6b7e2aa50bdaf88cd4c2a5e2059a7bf32d85a8b1] https://lava.sirena.=
org.uk/scheduler/job/1656585
# test job: [2291a2186305faaf8525d57849d8ba12ad63f5e7] https://lava.sirena.=
org.uk/scheduler/job/1655709
# test job: [a54ef14188519a0994d0264f701f5771815fa11e] https://lava.sirena.=
org.uk/scheduler/job/1656024
# test job: [a1d0b0ae65ae3f32597edfbb547f16c75601cd87] https://lava.sirena.=
org.uk/scheduler/job/1654201
# test job: [cf25eb8eae91bcae9b2065d84b0c0ba0f6d9dd34] https://lava.sirena.=
org.uk/scheduler/job/1654790
# test job: [595b7f155b926460a00776cc581e4dcd01220006] https://lava.sirena.=
org.uk/scheduler/job/1653119
# test job: [3059067fd3378a5454e7928c08d20bf3ef186760] https://lava.sirena.=
org.uk/scheduler/job/1655440
# test job: [2d86d2585ab929a143d1e6f8963da1499e33bf13] https://lava.sirena.=
org.uk/scheduler/job/1655917
# test job: [9a200cbdb54349909a42b45379e792e4b39dd223] https://lava.sirena.=
org.uk/scheduler/job/1654762
# test job: [162e23657e5379f07c6404dbfbf4367cb438ea7d] https://lava.sirena.=
org.uk/scheduler/job/1652978
# test job: [886f42ce96e7ce80545704e7168a9c6b60cd6c03] https://lava.sirena.=
org.uk/scheduler/job/1654270
# test job: [6684aba0780da9f505c202f27e68ee6d18c0aa66] https://lava.sirena.=
org.uk/scheduler/job/1738722
# test job: [be5d4872e528796df9d7425f2bd9b3893eb3a42c] https://lava.sirena.=
org.uk/scheduler/job/1778528
# bad: [be5d4872e528796df9d7425f2bd9b3893eb3a42c] Add linux-next specific f=
iles for 20250905
git bisect bad be5d4872e528796df9d7425f2bd9b3893eb3a42c
# test job: [c3ce85ecd0268df1e0ca692e8126bb181fc89a08] https://lava.sirena.=
org.uk/scheduler/job/1779086
# bad: [c3ce85ecd0268df1e0ca692e8126bb181fc89a08] Merge branch 'main' of ht=
tps://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git
git bisect bad c3ce85ecd0268df1e0ca692e8126bb181fc89a08
# test job: [973a887a5bb9a42878e276209592e0f75c287bb6] https://lava.sirena.=
org.uk/scheduler/job/1780104
# bad: [973a887a5bb9a42878e276209592e0f75c287bb6] Merge branch 'fs-next' of=
 linux-next
git bisect bad 973a887a5bb9a42878e276209592e0f75c287bb6
# test job: [fdabd8890022a9439b95d7395f7ae046544d96fd] https://lava.sirena.=
org.uk/scheduler/job/1780530
# bad: [fdabd8890022a9439b95d7395f7ae046544d96fd] Merge branch 'for-next' o=
f https://git.kernel.org/pub/scm/linux/kernel/git/qcom/linux.git
git bisect bad fdabd8890022a9439b95d7395f7ae046544d96fd
# test job: [94bd0249a4a06131c4a1c2097b6134217a658976] https://lava.sirena.=
org.uk/scheduler/job/1780904
# bad: [94bd0249a4a06131c4a1c2097b6134217a658976] Merge branch 'for-next' o=
f https://git.kernel.org/pub/scm/linux/kernel/git/soc/soc.git
git bisect bad 94bd0249a4a06131c4a1c2097b6134217a658976
# test job: [702b6c2f1008779e8fc8a4a4438410165309a4b4] https://lava.sirena.=
org.uk/scheduler/job/1781370
# bad: [702b6c2f1008779e8fc8a4a4438410165309a4b4] kasan-apply-write-only-mo=
de-in-kasan-kunit-testcases-v7
git bisect bad 702b6c2f1008779e8fc8a4a4438410165309a4b4
# test job: [0ac48805721d5952a920356e454167bba8d27737] https://lava.sirena.=
org.uk/scheduler/job/1781448
# good: [0ac48805721d5952a920356e454167bba8d27737] mm: convert page_to_sect=
ion() to memdesc_section()
git bisect good 0ac48805721d5952a920356e454167bba8d27737
# test job: [dc731eba2e47fa81d50aa1cb167100889253cfe0] https://lava.sirena.=
org.uk/scheduler/job/1781608
# good: [dc731eba2e47fa81d50aa1cb167100889253cfe0] mm/damon/paddr: support =
addr_unit for MIGRATE_{HOT,COLD}
git bisect good dc731eba2e47fa81d50aa1cb167100889253cfe0
# test job: [e24bb041cafabaa5fa3d76386c86af389cc324f5] https://lava.sirena.=
org.uk/scheduler/job/1781660
# good: [e24bb041cafabaa5fa3d76386c86af389cc324f5] mm/memremap: reject unre=
asonable folio/compound page sizes in memremap_pages()
git bisect good e24bb041cafabaa5fa3d76386c86af389cc324f5
# test job: [62fd63f4688f40f01a6df23225523ece10d4b69a] https://lava.sirena.=
org.uk/scheduler/job/1781975
# bad: [62fd63f4688f40f01a6df23225523ece10d4b69a] dma-remap: drop nth_page(=
) in dma_common_contiguous_remap()
git bisect bad 62fd63f4688f40f01a6df23225523ece10d4b69a
# test job: [cb42f7f6d9e4eff4e5259cddf82fd913306b8fe7] https://lava.sirena.=
org.uk/scheduler/job/1782145
# good: [cb42f7f6d9e4eff4e5259cddf82fd913306b8fe7] fs: hugetlbfs: remove nt=
h_page() usage within folio in adjust_range_hwpoison()
git bisect good cb42f7f6d9e4eff4e5259cddf82fd913306b8fe7
# test job: [db076b5db550aa34169dceee81d0974c7b2a2482] https://lava.sirena.=
org.uk/scheduler/job/1782813
# bad: [db076b5db550aa34169dceee81d0974c7b2a2482] mm/gup: remove record_sub=
pages()
git bisect bad db076b5db550aa34169dceee81d0974c7b2a2482
# test job: [891d0b3189945a5c37ce92c4e5337ec2c17b6378] https://lava.sirena.=
org.uk/scheduler/job/1782916
# good: [891d0b3189945a5c37ce92c4e5337ec2c17b6378] mm/pagewalk: drop nth_pa=
ge() usage within folio in folio_walk_start()
git bisect good 891d0b3189945a5c37ce92c4e5337ec2c17b6378
# test job: [21999f6315d786cbd21d5b2d0ad56f3f6125279f] https://lava.sirena.=
org.uk/scheduler/job/1783020
# good: [21999f6315d786cbd21d5b2d0ad56f3f6125279f] mm/gup: drop nth_page() =
usage within folio when recording subpages
git bisect good 21999f6315d786cbd21d5b2d0ad56f3f6125279f
# first bad commit: [db076b5db550aa34169dceee81d0974c7b2a2482] mm/gup: remo=
ve record_subpages()

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
5032553-9ec0-494c-8689-0e3a6a73853c%40sirena.org.uk.

--V80dSr/3LzMwjpsi
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmi+8z0ACgkQJNaLcl1U
h9C0HQf/YLILQMy3G3PZlLVziChCHgLklSdjOdu58eGRZBkdjWnggsnR8H+o1TRT
qrYLTwPAQ7TkDlNC/IpdZTn6fTQnbmy/5CpEidfBuHIth4hUPlGHOHWwwaHo92Gd
bJmRfogfYX4kma6egaQbjIHdXUWb3BHdc+K3JmaaPInJN0sRsX8Od85Oxtx4cRAW
2A6bXjqDo+7pLzkMx+1LI15r2lS9AtPy53xbumPlHVmIOmn76VnDG+TaKlD6XmmD
z3piY3bbxBbFy5iZuZbC/xvn1JCA5lp+OHriZcz+eB8UBWoReKPRtq0Ugar/jbfo
bOBx+BGSWZGrrkT+5KyatEb3cS3IWw==
=1t1P
-----END PGP SIGNATURE-----

--V80dSr/3LzMwjpsi--
