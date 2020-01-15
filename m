Return-Path: <kasan-dev+bncBAABB6667PYAKGQEDWDF4AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BEC613BDC8
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 11:54:52 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id d10sf10120497iod.19
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 02:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579085691; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxNzGxzLiKLKLAjgo1eLSlUdZwCc9Oaqv1/USYbPEdlvfDdcXbKoc/4ZuYgOtZ/bQH
         o5MLOH+neHANzj00GqbKZv3gFTSWnUa6ruuePU5x7PjX56M6y4hKZ5hh2znQLZlg9YG3
         x3uCMkqDhPGeeh/aNeQCn5jW4InvTkjmwxaKz/qn/ywLp4gfWSak7QP2BaPOXuWCMp1I
         lB2VWxvNbP/gvAZmTekGMfR8VR89WTQcv9jih22vAW4qkGDdJzS3evLV+td9p/Op2OVr
         Z3OCbfamPW1bvgGDeNp2rj0NAnst2WH7XQoRGatOBp9TWICAxiXfWoVcJYnCb3MfUyZJ
         6Ygw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=reIQAsGC0S5cn841aPxtFgzBI4YSZY0z/KWwwhvag80=;
        b=P1FtqHhFLMpU8LonR294aPgk7k4Di2HSSU6UAfhO62JbUAH1mfwBkwdasHPh+FfKxW
         6fSVf0lQywCbzzAngzdfZ88RmDRg3ZhPtA77C9WVmCuP+NdugiChJ6LxVs9L+SJpFRla
         zh2O7hT+x1Oyr6wODeaH2pu06/bvAYnzf8iOEgCvDf9iIhGw6uZqZUgU+LdkOyjUU44F
         YKiU/37WcRfsC82TdfF33KZqli4h1HGVkWGPvUhur5C8PbXoa9JnPy1hQojOYHEHpzMO
         dERDAYsaq+GTFPnYqyJRO73lC6AxPgjEFSAULepQ3jTZWsm84tS34+zazGIn8croGkfq
         0Z7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Ii7bwv+q;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=reIQAsGC0S5cn841aPxtFgzBI4YSZY0z/KWwwhvag80=;
        b=TAOBmRgadDrON0VXBId4WxoSYQ2ZUpE6irz8quQGRoZcMyVEd+GNb02LQrItT2kVXt
         EPl334eLkEp8DpOWVt1rWT++82T4g1t5XGep+tKFj3izE+cwD781taOiagsrE/sBfYFP
         rIZLlm4J7CU9ygnFqRJ5G8y4k1/oUoHavJ/jizBHuK6jAfyrRLvEyLIn76a5q+z3nc2W
         pydhLzNls/96PFJChRVnL7rQJ9r2GDkU+9im3LOK+l049sBHqsQu/kv1Syy+LoHUhFHE
         PhGE0lnDYbSnVOLTnIf/2gRpwYLVbyTAc5afcDcBEqGRnNOu4/lJV2OLgAGhelSVLHV0
         rY/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=reIQAsGC0S5cn841aPxtFgzBI4YSZY0z/KWwwhvag80=;
        b=GW60GGT0wTf5GkjZo4SpXFc9WWIplBh62ZN5DLS6OMh/IpdkhEayVueur5V3HckdnH
         J8+ZBleV9SLRg7HVvC6OzDPe2xzuMJ6+YmMktegUEhJjo/fkh0ZsY+XS1endWhuziDB2
         VnKKuuMKc6GySRZIQ7Ry40FJQjXEJlzdNEs5Le0+fBIM7ZImzJKmHABJVOrPRP6GeL7b
         MWyvgxpe0ZXIVlxITva9ot6nu3KKoTbBlaYEa5VROCdqQnRj5brPg36r1/eQi3O2705a
         BJZct8YdMQHP6CURit0icdzJ5D6tCyI6jAWaJ5fqlXoIOIIM/LMSGI/QGtPfc1eq0cth
         jMVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXnSTPlcZ+LMf89DIjVuIMI1REXe6KWdQ/IAF8yzZUjN1+XnTUU
	2rWyD7ff0iwGaPzky+BCQ7c=
X-Google-Smtp-Source: APXvYqwjgv478Lq09cvjXVQPEM2YIOr5BrTPt81k6D4kJTeD195pH6M44QVxMqfC3q8MteuxJcauZQ==
X-Received: by 2002:a92:d451:: with SMTP id r17mr2846053ilm.201.1579085691186;
        Wed, 15 Jan 2020 02:54:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c734:: with SMTP id h20ls1529933jao.9.gmail; Wed, 15 Jan
 2020 02:54:50 -0800 (PST)
X-Received: by 2002:a02:c4da:: with SMTP id h26mr23763165jaj.47.1579085690858;
        Wed, 15 Jan 2020 02:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579085690; cv=none;
        d=google.com; s=arc-20160816;
        b=Tq5VaMZp8EWQxLM4OQQsa+jGeBDvRE2LfIFZSNDmozbQFsVX8w88XgUPzKQ3CrIjwG
         0YHDaNDCbM4XV36fU9zbrUsap4o7H1vuwUDgXBFJXPfWEBMHMIpa2V/k0sO1tnUA61BW
         TvWu23Zv+ghUA6X29toanrkd5XgwinImsYlyVFOatiaCO0qF8SNv2/bxSCsLVrIu3l2U
         90poV/sx7Hpn4a0UgDKnwZXhWsqffYYiZDD6Ktlp60VGUnwpOyiV6Y/6GRXAZtiTD+bO
         gBonVxyRFtw4QVihBToW9HsW4IlozSWl9ENoA/S6XlS5sWtusDCuhEGBbkY6H7xLrd4j
         K6aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=Xwop0XYeB4bDP0QAcShdQ/As5ZGHZMtgfAAeSALsvvk=;
        b=LPUrs8UNcxI4XV15lLH371+JAvHlnGxe5Z66Ml/54xTwyoTAEgfFpqURd8MrpnqiBM
         RfVlgJoNvCid9tid/nTp3mok/txsIjFCfTbiSfxRac/I95mvu28ZJBoRmebIap5xFsyd
         40upmQgIlpSt5dqrTCKI7QuzZALm87db+mPk5LyNa3n95bJm2U3RB7e9KiLaLPSBqEcc
         lMMet45yEVJVjfD1zQA8Wk1OON27suci4sm/3ILUAq0Kx+wsbYbzuFtqVF0RuWmBM//m
         krqFNmmcgA7VO8H/vFUzHF1BTEo+y9diMmF4g4iW+8SFwarshGY98K+UpdZ1BGImrRAr
         y+NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Ii7bwv+q;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa1.hc3370-68.iphmx.com (esa1.hc3370-68.iphmx.com. [216.71.145.142])
        by gmr-mx.google.com with ESMTPS id i4si785342ioi.1.2020.01.15.02.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 02:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) client-ip=216.71.145.142;
Received-SPF: None (esa1.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa1.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa1.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: 8vnPUVL20+CvVAJWJD85khQfIOSnPqu0B+Er7JkKHXTdCo+UTQIF497/lLCTw15rM6VfeOFUgH
 Ix3WmP83OThzJn2DzWh9ahOEMop+BdNMldmBWXwzyBXwGNWlId/98nkjjTg00ZXepcMoFhY6AN
 T7jtR9DIFe7xRMzbdDZn4NhTbo6g28XT+WuIvH17ODFV2hfxmR7CNDTMXh6xBHMXffVvJSClMJ
 5PYgaHrQJHMit11ZOLHXYjxeHsKN4LLS+LQkLCDHvq0ZSZVct8+yXcycojHs1B3bsHXjdvycCW
 GFg=
X-SBRS: 2.7
X-MesageID: 11102939
X-Ironport-Server: esa1.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,322,1574139600"; 
   d="scan'208";a="11102939"
Subject: Re: [PATCH v1 1/4] kasan: introduce set_pmd_early_shadow()
To: Juergen Gross <jgross@suse.com>
CC: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Stefano Stabellini <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, "sergey.dyasli@citrix.com >>
 Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-2-sergey.dyasli@citrix.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 xsFNBFtMVHEBEADc/hZcLexrB6vGTdGqEUsYZkFGQh6Z1OO7bCtM1go1RugSMeq9tkFHQSOc
 9c7W9NVQqLgn8eefikIHxgic6tGgKoIQKcPuSsnqGao2YabsTSSoeatvmO5HkR0xGaUd+M6j
 iqv3cD7/WL602NhphT4ucKXCz93w0TeoJ3gleLuILxmzg1gDhKtMdkZv6TngWpKgIMRfoyHQ
 jsVzPbTTjJl/a9Cw99vuhFuEJfzbLA80hCwhoPM+ZQGFDcG4c25GQGQFFatpbQUhNirWW5b1
 r2yVOziSJsvfTLnyzEizCvU+r/Ek2Kh0eAsRFr35m2X+X3CfxKrZcePxzAf273p4nc3YIK9h
 cwa4ZpDksun0E2l0pIxg/pPBXTNbH+OX1I+BfWDZWlPiPxgkiKdgYPS2qv53dJ+k9x6HkuCy
 i61IcjXRtVgL5nPGakyOFQ+07S4HIJlw98a6NrptWOFkxDt38x87mSM7aSWp1kjyGqQTGoKB
 VEx5BdRS5gFdYGCQFc8KVGEWPPGdeYx9Pj2wTaweKV0qZT69lmf/P5149Pc81SRhuc0hUX9K
 DnYBa1iSHaDjifMsNXKzj8Y8zVm+J6DZo/D10IUxMuExvbPa/8nsertWxoDSbWcF1cyvZp9X
 tUEukuPoTKO4Vzg7xVNj9pbK9GPxSYcafJUgDeKEIlkn3iVIPwARAQABzShTZXJnZXkgRHlh
 c2xpIDxzZXJnZXkuZHlhc2xpQGNpdHJpeC5jb20+wsGlBBMBCgA4FiEEkI7HMI5EbM2FLA1L
 Aa+w5JvbyusFAltMVHECGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AAIQkQAa+w5JvbyusW
 IQSQjscwjkRszYUsDUsBr7Dkm9vK65AkEACvL+hErqbQj5yTVNqvP1rVGsXvevViglSTkHD4
 9LGwEk4+ne8N4DPcqrDnyqYFd42UxTjVyoDEXEIIoy0RHWCmaspYEDX8fVmgFG3OFoeA9NAv
 JHssHU6B2mDAQ6M3VDmAwTw+TbXL/c1wblgGAP9kdurydZL8bevTTUh7edfnm5pwaT9HLXvl
 xLjz5qyt6tKEowM0xPVzCKaj3Mf/cuZFOlaWiHZ0biOPC0JeoHuz4UQTnBBUKk+n2nnn72k9
 37cNeaxARwn/bxcej9QlbrrdaNGVFzjCA/CIL0KjUepowpLN0+lmYjkPgeLNYfyMXumlSNag
 9qnCTh0QDsCXS/HUHPeBskAvwNpGBCkfiP/XqJ+V618ZQ1sclHa9aWNnlIR/a8xVx25t/14V
 R8EX/045HUpyPU8hI/yw+Fw/ugJ8W0dFzFeHU5K2tEW2W0m3ZWWWgpcBSCB17DDLIPjGX1Qc
 J8jiVJ7E4rfvA1JBg9BxVw5LVuXg2FB6bqnDYALfY2ydATk+ZzMUAMMilaE7/5a2RMV4TYcd
 8Cf77LdgO0pB3vF6z1QmNA2IbOICtJOXpmvHj+dKFUt5hFVbvqXbuAjlrwFktbAFVGxaeIYz
 nQ44lQu9JqDuSH5yOytdek24Dit8SgEHGvumyj17liCG6kNzxd+2xh3uaUCA5MIALy5mZ87B
 TQRbTFRxARAAwqL3u/cPDA+BhU9ghtAkC+gyC5smWUL1FwTQ9CwTqcQpKt85PoaHn8sc5ctt
 Aj2fNT/F2vqQx/BthVOdkhj9LCwuslqBIqbri3XUyMLVV/Tf+ydzHW2AjufCowwgBguxedD1
 f9Snkv+As7ZgMg/GtDqDiCWBFg9PneKvr+FPPd2WmrI8Kium4X5Zjs/a6OGUWVcIBoPpu088
 z/0tlKYjTFLhoIEsf6ll4KvRQZIyGxclg3RBEuN+wgMbKppdUf2DBXYeCyrrPx809CUFzcik
 O99drWti2CV1gF8bnbUvfCewxwqgVKtHl2kfsm2+/lgG4CTyvnvWqUyHICZUqISdz5GidaXn
 TcPlsAeo2YU2NXbjwnmxzJEP/4FxgsjYIUbbxdmsK+PGre7HmGmaDZ8K77L3yHr/K7AH8mFs
 WUM5KiW4SnKyIQvdHkZMpvE4XrrirlZ+JI5vE043GzzpS2CGo0NFQmDJLRbpN/KQY6dkNVgA
 L0aDxJtAO1rXKYDSrvpL80bYyskQ4ivUa06v9SM2/bHi9bnp3Nf/fK6ErWKWmDOHWrnTgRML
 oQpcxoVPxw2CwyWT1069Y/CWwgnbj34+LMwMUYhPEZMitABpQE74dEtIFh0c2scm3K2QGhOP
 KQK3szqmXuX6MViMZLDh/B7FXLQyqwMBnZygfzZFM9vpDskAEQEAAcLBjQQYAQoAIBYhBJCO
 xzCORGzNhSwNSwGvsOSb28rrBQJbTFRxAhsMACEJEAGvsOSb28rrFiEEkI7HMI5EbM2FLA1L
 Aa+w5Jvbyuvvbg//S3d1+XL568K5BTHXaYxSqCeMqYbV9rPhEHyk+rzKtwNXSbSO8x0xZutL
 gYV+nkW0KMPH5Bz3I1xiRKAkiX/JLcMfx2HAXJ1Cv2rpR6bxyCGBJmuwR68uMS/gKe6AWwTY
 q2kt1rtZPjGl9OwVoWGJKbu2pFBLWmLAnHlXOL6WDSE1Mz2Ah3jMHOaSyAgPu1XSNa600gMJ
 QrSxgbe7bW72gCjeHcrIjfv+uh5cZ5/J/edpWXRuE4Tz82nxudBIHE2vnQEoJrXOh2kAJiYs
 G+IllDqFKDPrnS0R3DenBNG0Ir8h9W6heETnhQUc9NDFCSr81Mp0fROdBfYZnQzgSZMjN2eY
 pkNEWshJER4ZYY+7hAmqI51HnsKuM46QINh00jJHRMykW3TBMlwnUFxZ0gplAecjCFC7g2zj
 g1qNxLnxMS4wCsyEVhCkPyYnS8zuoa4ZUH37CezD01Ph4O1saln5+M4blHCEAUpZIkTGpUoi
 SEwtoxu6EEUYfbcjWgzJCs023hbRykZlFALoRNCwVz/FnPuVu291jn9kjvCTEeE6g2dCtOrO
 ukuXzk1tIeeoggsU7AJ0bzP7QOEhEckaBbP4k6ic26LJGWNMinllePyEMXzsgmMHVN//8wDT
 NWaanhP/JZ1v5Mfn8s1chIqC0sJIw73RvvuBkOa+jx0OwW3RFoQ=
Message-ID: <96c2414e-91fb-5a28-44bc-e30d2daabec5@citrix.com>
Date: Wed, 15 Jan 2020 10:54:45 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20200108152100.7630-2-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=Ii7bwv+q;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

Hi Juergen,

On 08/01/2020 15:20, Sergey Dyasli wrote:
> It is incorrect to call pmd_populate_kernel() multiple times for the
> same page table. Xen notices it during kasan_populate_early_shadow():
>
>     (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>
> This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
> enabled. Fix this by introducing set_pmd_early_shadow() which calls
> pmd_populate_kernel() only once and uses set_pmd() afterwards.
>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>

Looks like the plan to use set_pmd() directly has failed: it's an
arch-specific function and can't be used in arch-independent code
(as kbuild test robot has proven).

Do you see any way out of this other than disabling SPLIT_PTE_PTLOCKS
for PV KASAN?

--
Thanks,
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96c2414e-91fb-5a28-44bc-e30d2daabec5%40citrix.com.
